from __future__ import annotations

import multiprocessing as mp
import time
from typing import Any


PAGE_SIZE = 0x1000
DEFAULT_MAX_STEPS = 20_000
DEFAULT_TRACE_LIMIT = 128
DEFAULT_WRITE_LIMIT = 64


def _int_value(value: Any, default: int | None = None) -> int | None:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return int(str(value).strip(), 0)


def _align_down(value: int) -> int:
    return value & ~(PAGE_SIZE - 1)


def _align_up(value: int) -> int:
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def _architecture(snapshot: dict[str, Any]) -> tuple[str, int, str]:
    data = snapshot.get("architecture") if isinstance(snapshot.get("architecture"), dict) else {}
    name = str(data.get("name") or data.get("arch") or data.get("processor") or "x86").lower()
    bits = int(data.get("bits") or data.get("bitness") or 64)
    endian = str(data.get("endian") or "little").lower()
    if "aarch64" in name or "arm64" in name or (name.startswith("arm") and bits == 64):
        return "arm64", 64, endian
    if name.startswith("arm"):
        return "arm", bits if bits in {32, 64} else 32, endian
    if "ppc" in name or "powerpc" in name:
        return "ppc", bits if bits in {32, 64} else 64, endian
    if name in {"x86", "x86-16", "x86-32", "x86-64", "i386", "i686", "amd64", "metapc"}:
        return "x86", bits if bits in {16, 32, 64} else 64, endian
    return "unsupported", bits, endian


def _register_ids(arch: str, bits: int) -> dict[str, Any]:
    if arch == "x86":
        from unicorn import x86_const as c

        names = ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP", "EFLAGS") if bits == 64 else ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFLAGS")
        return {name: getattr(c, f"UC_X86_REG_{name}") for name in names}
    if arch == "arm64":
        from unicorn import arm64_const as c

        return {**{f"X{index}": getattr(c, f"UC_ARM64_REG_X{index}") for index in range(31)}, "SP": c.UC_ARM64_REG_SP, "PC": c.UC_ARM64_REG_PC, "NZCV": c.UC_ARM64_REG_NZCV}
    if arch == "arm":
        from unicorn import arm_const as c

        return {**{f"R{index}": getattr(c, f"UC_ARM_REG_R{index}") for index in range(13)}, "SP": c.UC_ARM_REG_SP, "LR": c.UC_ARM_REG_LR, "PC": c.UC_ARM_REG_PC, "CPSR": c.UC_ARM_REG_CPSR}
    if arch == "ppc":
        from unicorn import ppc_const as c

        return {**{f"R{index}": getattr(c, f"UC_PPC_REG_{index}") for index in range(32)}, "PC": c.UC_PPC_REG_PC, "CR": c.UC_PPC_REG_CR, "LR": c.UC_PPC_REG_LR}
    raise ValueError(f"Unsupported replay architecture: {arch}")


def _mode(arch: str, bits: int, endian: str, snapshot: dict[str, Any]) -> int:
    from unicorn import (
        UC_MODE_16,
        UC_MODE_32,
        UC_MODE_64,
        UC_MODE_ARM,
        UC_MODE_BIG_ENDIAN,
        UC_MODE_LITTLE_ENDIAN,
        UC_MODE_PPC32,
        UC_MODE_PPC64,
        UC_MODE_THUMB,
    )

    mode_data = snapshot.get("architecture") if isinstance(snapshot.get("architecture"), dict) else {}
    mode_name = str(mode_data.get("mode") or "").lower()
    endian_mode = UC_MODE_BIG_ENDIAN if endian == "big" else UC_MODE_LITTLE_ENDIAN
    if arch == "x86":
        return {16: UC_MODE_16, 32: UC_MODE_32, 64: UC_MODE_64}[bits]
    if arch == "arm64":
        return endian_mode
    if arch == "arm":
        return endian_mode | (UC_MODE_THUMB if mode_name == "thumb" else UC_MODE_ARM)
    if arch == "ppc":
        return endian_mode | (UC_MODE_PPC64 if bits == 64 else UC_MODE_PPC32)
    raise ValueError(f"Unsupported replay architecture: {arch}")


def _memory_pages(snapshot: dict[str, Any]) -> tuple[dict[int, bytearray], dict[int, str]]:
    pages: dict[int, bytearray] = {}
    permissions: dict[int, set[str]] = {}
    for item in snapshot.get("memory") or []:
        if not isinstance(item, dict):
            continue
        start = _int_value(item.get("start", item.get("base")))
        if start is None:
            continue
        raw = item.get("data", "")
        if not isinstance(raw, str):
            continue
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            continue
        perm = set(str(item.get("perm") or "rwx").lower()) & {"r", "w", "x"}
        if not perm:
            perm = {"r", "w", "x"}
        for offset, value in enumerate(data):
            address = start + offset
            page = _align_down(address)
            page_data = pages.setdefault(page, bytearray(PAGE_SIZE))
            page_data[address - page] = value
            permissions.setdefault(page, set()).update(perm)
    return pages, {page: "".join(flag for flag in "rwx" if flag in perm) for page, perm in permissions.items()}


def _permission_flags(permission: str) -> int:
    from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE

    flags = 0
    if "r" in permission:
        flags |= UC_PROT_READ
    if "w" in permission:
        flags |= UC_PROT_WRITE
    if "x" in permission:
        flags |= UC_PROT_EXEC
    return flags or UC_PROT_READ


def _reg_value(registers: dict[str, Any], name: str) -> int | None:
    if name in registers:
        return _int_value(registers[name])
    upper = name.upper()
    for key, value in registers.items():
        if str(key).upper() == upper:
            return _int_value(value)
    return None


def _set_registers(uc: Any, ids: dict[str, Any], registers: dict[str, Any]) -> None:
    for name, reg_id in ids.items():
        value = _reg_value(registers, name)
        if value is not None:
            uc.reg_write(reg_id, value)


def _unknown_registers(ids: dict[str, Any], registers: Any) -> list[str]:
    if not isinstance(registers, dict):
        return []
    known = {str(name).upper() for name in ids}
    return [str(name) for name in registers if str(name).upper() not in known]


def _get_registers(uc: Any, ids: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, reg_id in ids.items():
        try:
            result[name] = f"0x{int(uc.reg_read(reg_id)):X}"
        except Exception:
            continue
    return result


def _apply_memory_patches(uc: Any, mapped: set[int], patches: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    applied: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    if not isinstance(patches, list):
        return applied, failed
    for item in patches:
        if not isinstance(item, dict):
            failed.append({"ok": False, "error": "patch must be an object"})
            continue
        address = _int_value(item.get("addr", item.get("address")))
        raw = item.get("data", item.get("bytes", ""))
        if address is None or not isinstance(raw, str):
            failed.append({"ok": False, "error": "patch requires numeric addr and hex data"})
            continue
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            failed.append({"ok": False, "addr": f"0x{address:X}", "error": "patch data is not valid hex"})
            continue
        if not data:
            failed.append({"ok": False, "addr": f"0x{address:X}", "error": "patch data is empty"})
            continue
        pages = {_align_down(address + offset) for offset in range(len(data))}
        if not pages.issubset(mapped):
            failed.append({"ok": False, "addr": f"0x{address:X}", "size": len(data), "error": "patch range is not captured; add the region to the snapshot"})
            continue
        try:
            uc.mem_write(address, data)
        except Exception as exc:
            failed.append({"ok": False, "addr": f"0x{address:X}", "size": len(data), "error": str(exc)})
            continue
        applied.append({"ok": True, "addr": f"0x{address:X}", "size": len(data)})
    return applied, failed


def _readback_memory(uc: Any, mapped: set[int], regions: Any) -> list[dict[str, Any]]:
    if not isinstance(regions, list):
        return []
    result: list[dict[str, Any]] = []
    total = 0
    for index, item in enumerate(regions):
        if not isinstance(item, dict):
            result.append({"index": index, "ok": False, "error": "readback region must be an object"})
            continue
        address = _int_value(item.get("addr", item.get("start")))
        size = _int_value(item.get("size"), 0) or 0
        if address is None or size < 1 or size > 64 * 1024:
            result.append({"index": index, "ok": False, "error": "readback requires addr and size 1..65536"})
            continue
        if total + size > 256 * 1024:
            result.append({"index": index, "addr": f"0x{address:X}", "ok": False, "error": "readback limit exceeded"})
            continue
        pages = {_align_down(address + offset) for offset in range(size)}
        missing = sorted(page for page in pages if page not in mapped)
        if missing:
            result.append({
                "index": index,
                "addr": f"0x{address:X}",
                "size": size,
                "ok": False,
                "missing_pages": [f"0x{page:X}" for page in missing],
            })
            continue
        try:
            data = bytes(uc.mem_read(address, size))
        except Exception as exc:
            result.append({"index": index, "addr": f"0x{address:X}", "size": size, "ok": False, "error": str(exc)})
            continue
        total += size
        result.append({"index": index, "addr": f"0x{address:X}", "size": size, "ok": True, "data": data.hex()})
    return result


def _parse_inspect_points(arguments: Any, ids: dict[str, Any]) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(arguments, dict) or arguments.get("inspect") is None:
        return {}, []
    raw_points = arguments.get("inspect")
    if not isinstance(raw_points, list):
        return {}, [{"index": -1, "error": "inspect must be a list"}]
    points: dict[int, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    for index, item in enumerate(raw_points):
        if not isinstance(item, dict):
            errors.append({"index": index, "error": "inspect point must be an object"})
            continue
        address = _int_value(item.get("at", item.get("addr")))
        registers = item.get("registers") if isinstance(item.get("registers"), list) else []
        memory = item.get("memory") if isinstance(item.get("memory"), list) else []
        max_hits = _int_value(item.get("max_hits"), 1) or 1
        if address is None:
            errors.append({"index": index, "error": "inspect point requires numeric at"})
        elif max_hits < 1 or max_hits > 1000:
            errors.append({"index": index, "addr": f"0x{address:X}", "error": "max_hits must be 1..1000"})
        elif address in points:
            errors.append({"index": index, "addr": f"0x{address:X}", "error": "duplicate inspect address"})
        else:
            unknown = [str(name) for name in registers if str(name).upper() not in {str(key).upper() for key in ids}]
            if unknown:
                errors.append({"index": index, "addr": f"0x{address:X}", "error": "unknown inspect registers", "registers": unknown})
            else:
                points[address] = {"id": str(item.get("id") or f"inspect-{index}"), "addr": address, "registers": registers, "memory": memory, "max_hits": max_hits}
    return points, errors


def _expand_breakpoints(arguments: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(arguments, dict) or arguments.get("breakpoints") is None:
        return [], [], []
    raw_points = arguments.get("breakpoints")
    if not isinstance(raw_points, list):
        return [], [], [{"index": -1, "error": "breakpoints must be a list"}]
    hooks: list[dict[str, Any]] = []
    inspections: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, item in enumerate(raw_points):
        if not isinstance(item, dict):
            errors.append({"index": index, "error": "breakpoint must be an object"})
            continue
        address = item.get("at", item.get("addr"))
        action = str(item.get("action") or "inspect").strip().lower()
        if action not in {"inspect", "skip"}:
            errors.append({"index": index, "error": "breakpoint action must be inspect or skip"})
            continue
        point = {
            "id": str(item.get("id") or f"breakpoint-{index}"),
            "at": address,
            "registers": item.get("capture_registers") if isinstance(item.get("capture_registers"), list) else [],
            "memory": item.get("capture_memory") if isinstance(item.get("capture_memory"), list) else [],
            "max_hits": item.get("max_hits", 1),
        }
        inspections.append(point)
        if action == "skip":
            hooks.append({
                "id": point["id"],
                "addr": address,
                "action": "skip",
                "size": item.get("size"),
                "registers": item.get("set_registers") if isinstance(item.get("set_registers"), dict) else {},
                "writes": item.get("writes") if isinstance(item.get("writes"), list) else [],
                "max_hits": item.get("max_hits", 1),
            })
    return hooks, inspections, errors


def _parse_hooks(arguments: Any) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(arguments, dict) or arguments.get("hooks") is None:
        return {}, []
    raw_hooks = arguments.get("hooks")
    if not isinstance(raw_hooks, list):
        return {}, [{"index": -1, "error": "hooks must be a list"}]
    hooks: dict[int, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    for index, item in enumerate(raw_hooks):
        if not isinstance(item, dict):
            errors.append({"index": index, "error": "hook must be an object"})
            continue
        address = _int_value(item.get("addr", item.get("address")))
        action = str(item.get("action") or "").strip().lower()
        size = _int_value(item.get("size"), 0) or 0
        max_hits = _int_value(item.get("max_hits"), 1) or 1
        registers = item.get("registers") if isinstance(item.get("registers"), dict) else {}
        writes = item.get("writes") if isinstance(item.get("writes"), list) else []
        if address is None:
            errors.append({"index": index, "error": "hook requires numeric addr"})
        elif action != "skip":
            errors.append({"index": index, "addr": f"0x{address:X}", "error": "only action=skip is supported"})
        elif size < 1 or size > 32:
            errors.append({"index": index, "addr": f"0x{address:X}", "error": "hook size must be 1..32"})
        elif max_hits < 1 or max_hits > 1000:
            errors.append({"index": index, "addr": f"0x{address:X}", "error": "max_hits must be 1..1000"})
        elif address in hooks:
            errors.append({"index": index, "addr": f"0x{address:X}", "error": "duplicate hook address"})
        else:
            hooks[address] = {
                "id": str(item.get("id") or f"hook-{index}"),
                "addr": address,
                "size": size,
                "max_hits": max_hits,
                "registers": registers,
                "writes": writes,
            }
    return hooks, errors


def _argument_registers(arch: str, bits: int, abi: str) -> list[str]:
    normalized_abi = abi.lower()
    if arch == "x86" and bits == 64:
        if normalized_abi in {"sysv", "sysv64", "unix"}:
            return ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]
        return ["RCX", "RDX", "R8", "R9"]
    if arch == "x86":
        return ["ECX", "EDX"]
    if arch == "arm64":
        return [f"X{index}" for index in range(8)]
    if arch == "arm":
        return [f"R{index}" for index in range(4)]
    if arch == "ppc":
        return [f"R{index}" for index in range(3, 11)]
    return []


def _emulate_once(snapshot: dict[str, Any], arguments: Any, max_steps: int, trace_limit: int, write_limit: int) -> dict[str, Any]:
    try:
        from unicorn import (
            Uc,
            UcError,
            UC_HOOK_CODE,
            UC_HOOK_MEM_FETCH_UNMAPPED,
            UC_HOOK_MEM_FETCH_PROT,
            UC_HOOK_MEM_READ_UNMAPPED,
            UC_HOOK_MEM_READ_PROT,
            UC_HOOK_MEM_WRITE,
            UC_HOOK_MEM_WRITE_UNMAPPED,
            UC_HOOK_MEM_WRITE_PROT,
        )
    except ImportError as exc:
        return {"ok": False, "error": "Unicorn is not installed", "detail": str(exc)}

    arch, bits, endian = _architecture(snapshot)
    if arch == "unsupported":
        return {"ok": False, "error": "Unsupported replay architecture", "architecture": {"name": arch, "bits": bits, "endian": endian}}
    if arch == "ppc" and bits == 64:
        return {"ok": False, "error": "PPC64 replay is not supported by this Unicorn build", "architecture": {"name": arch, "bits": bits, "endian": endian}}
    try:
        from unicorn import (
            UC_ARCH_ARM,
            UC_ARCH_ARM64,
            UC_ARCH_PPC,
            UC_ARCH_X86,
        )

        arch_id = {"x86": UC_ARCH_X86, "arm": UC_ARCH_ARM, "arm64": UC_ARCH_ARM64, "ppc": UC_ARCH_PPC}[arch]
        ids = _register_ids(arch, bits)
        uc = Uc(arch_id, _mode(arch, bits, endian, snapshot))
    except Exception as exc:
        return {"ok": False, "error": "Unable to initialize Unicorn", "detail": str(exc)}

    pages, page_permissions = _memory_pages(snapshot)
    mapped: set[int] = set()
    try:
        for page, data in sorted(pages.items()):
            uc.mem_map(page, PAGE_SIZE)
            uc.mem_write(page, bytes(data))
            uc.mem_protect(page, PAGE_SIZE, _permission_flags(page_permissions.get(page, "rwx")))
            mapped.add(page)
    except Exception as exc:
        return {"ok": False, "error": "Unable to map replay memory", "detail": str(exc), "mapped_pages": len(mapped)}

    registers = snapshot.get("registers") if isinstance(snapshot.get("registers"), dict) else {}
    try:
        _set_registers(uc, ids, registers)
    except Exception as exc:
        return {"ok": False, "error": "Unable to restore registers", "detail": str(exc)}

    sp_name = "RSP" if arch == "x86" and bits == 64 else "ESP" if arch == "x86" else "SP" if arch in {"arm", "arm64"} else "R1"
    pc_name = "RIP" if arch == "x86" and bits == 64 else "EIP" if arch == "x86" else "PC"
    sp = _reg_value(registers, sp_name)
    if sp is None:
        stack_base = 0x700000000000 if bits == 64 else 0x70000000
        while _align_down(stack_base) in mapped:
            stack_base += 0x100000
        stack_size = 0x20000
        uc.mem_map(stack_base, stack_size)
        mapped.update(range(stack_base, stack_base + stack_size, PAGE_SIZE))
        sp = stack_base + stack_size // 2
        uc.reg_write(ids[sp_name], sp)
    else:
        # An explicit stack pointer comes from the captured process state. Do
        # not fill surrounding pages with zeroes: missing stack data must be
        # reported as a fault so the host can capture the real page.
        pass

    argument_values = arguments if isinstance(arguments, list) else []
    patch_values: Any = None
    if isinstance(arguments, dict):
        overrides = arguments.get("registers")
        if isinstance(overrides, dict):
            unknown = _unknown_registers(ids, overrides)
            if unknown:
                return {"ok": False, "error": "Unknown replay registers", "registers_failed": unknown}
            _set_registers(uc, ids, overrides)
        argument_values = arguments.get("args") if isinstance(arguments.get("args"), list) else []
        patch_values = arguments.get("memory_patches")
    patches_applied, patches_failed = _apply_memory_patches(uc, mapped, patch_values)
    if patches_failed:
        return {
            "ok": False,
            "error": "Replay memory patch failed",
            "stop_reason": "patch_error",
            "patches_applied": patches_applied,
            "patches_failed": patches_failed,
        }
    abi = str(snapshot.get("abi") or ("sysv64" if arch == "x86" and bits == 64 else "win64"))
    for name, value in zip(_argument_registers(arch, bits, abi), argument_values, strict=False):
        if name in ids:
            uc.reg_write(ids[name], _int_value(value, 0) or 0)

    thumb_mode = arch == "arm" and str((snapshot.get("architecture") or {}).get("mode") or "").lower() == "thumb"
    sentinel = 0x7FFE00000000 if bits == 64 else 0x7FFE0000
    if thumb_mode:
        sentinel |= 1
    sentinel_page = _align_down(sentinel)
    if sentinel_page not in mapped:
        uc.mem_map(sentinel_page, PAGE_SIZE)
        mapped.add(sentinel_page)
    try:
        if arch == "x86":
            uc.mem_write(sp, int(sentinel).to_bytes(8 if bits == 64 else 4, "little"))
        elif arch == "arm64":
            uc.reg_write(ids["X30"], sentinel)
        elif arch == "arm":
            uc.reg_write(ids["LR"], sentinel)
        elif arch == "ppc":
            uc.reg_write(ids["LR"], sentinel)
    except Exception:
        pass

    entry = _int_value(snapshot.get("entry"))
    if entry is None:
        entry = _int_value((snapshot.get("function") or {}).get("start")) if isinstance(snapshot.get("function"), dict) else None
    if entry is None:
        return {"ok": False, "error": "Replay snapshot has no entry address"}
    entry_pc = entry | 1 if thumb_mode else entry

    breakpoint_hooks, breakpoint_inspections, breakpoint_errors = _expand_breakpoints(arguments)
    parse_arguments = dict(arguments) if isinstance(arguments, dict) else {}
    parse_arguments["hooks"] = list(parse_arguments.get("hooks") or []) + breakpoint_hooks
    parse_arguments["inspect"] = list(parse_arguments.get("inspect") or []) + breakpoint_inspections
    hooks, hook_errors = _parse_hooks(parse_arguments)
    hook_errors = breakpoint_errors + hook_errors
    for hook in hooks.values():
        unknown = _unknown_registers(ids, hook["registers"])
        if unknown:
            hook_errors.append({"id": hook["id"], "addr": f"0x{int(hook['addr']):X}", "error": "unknown hook registers", "registers": unknown})
    if hook_errors:
        return {"ok": False, "error": "Invalid replay hooks", "hooks_failed": hook_errors}
    inspect_points, inspect_errors = _parse_inspect_points(parse_arguments, ids)
    if inspect_errors:
        return {"ok": False, "error": "Invalid replay inspect points", "inspect_failed": inspect_errors}

    trace: list[str] = []
    writes: list[dict[str, Any]] = []
    fault: dict[str, Any] = {}
    hooks_applied: list[dict[str, Any]] = []
    hooks_failed: list[dict[str, Any]] = []
    hook_hits: dict[int, int] = {}
    inspect_hits: dict[int, int] = {}
    observations: list[dict[str, Any]] = []
    steps = 0
    stop_reason = ""

    def apply_hook(hook: dict[str, Any]) -> None:
        nonlocal stop_reason
        address = int(hook["addr"])
        hit = hook_hits.get(address, 0) + 1
        hook_hits[address] = hit
        try:
            _set_registers(uc, ids, hook["registers"])
            applied, failed = _apply_memory_patches(uc, mapped, hook["writes"])
            if failed:
                hooks_failed.append({"id": hook["id"], "addr": f"0x{address:X}", "hit": hit, "writes_failed": failed})
                stop_reason = "hook_error"
                uc.emu_stop()
                return
            next_pc = (address & ~1 if thumb_mode else address) + int(hook["size"])
            if thumb_mode:
                next_pc |= 1
            uc.reg_write(ids[pc_name], next_pc)
            hooks_applied.append({
                "id": hook["id"],
                "addr": f"0x{address:X}",
                "hit": hit,
                "size": int(hook["size"]),
                "registers": {str(name).upper(): str(value) for name, value in hook["registers"].items()},
                "writes": applied,
            })
        except Exception as exc:
            hooks_failed.append({"id": hook["id"], "addr": f"0x{address:X}", "hit": hit, "error": str(exc)})
            stop_reason = "hook_error"
            uc.emu_stop()

    def on_code(uc_obj: Any, address: int, size: int, _user_data: Any) -> None:
        nonlocal steps, stop_reason
        steps += 1
        if len(trace) < trace_limit:
            trace.append(f"0x{address:X}")
        if address == sentinel or (thumb_mode and address == (sentinel & ~1)):
            stop_reason = "return"
            uc_obj.emu_stop()
            return
        point = inspect_points.get(address) or (inspect_points.get(address & ~1) if thumb_mode else None)
        if point:
            if inspect_hits.get(int(point["addr"]), 0) < int(point["max_hits"]):
                inspect_hits[int(point["addr"])] = inspect_hits.get(int(point["addr"]), 0) + 1
                selected = {str(name).upper() for name in point["registers"]}
                registers_after = _get_registers(uc_obj, ids)
                observations.append({
                    "id": point["id"],
                    "addr": f"0x{int(point['addr']):X}",
                    "hit": inspect_hits[int(point["addr"])],
                    "registers": {name: value for name, value in registers_after.items() if not selected or name in selected},
                    "memory": _readback_memory(uc_obj, mapped, point["memory"]),
                })
        hook = hooks.get(address) or (hooks.get(address & ~1) if thumb_mode else None)
        if hook:
            if hook_hits.get(address, 0) >= int(hook["max_hits"]):
                hooks_failed.append({"id": hook["id"], "addr": f"0x{address:X}", "error": "hook max_hits exceeded"})
                stop_reason = "hook_limit"
                uc_obj.emu_stop()
            else:
                apply_hook(hook)

    def on_write(_uc_obj: Any, _access: int, address: int, size: int, value: int, _user_data: Any) -> None:
        if len(writes) < write_limit:
            writes.append({"addr": f"0x{address:X}", "size": int(size), "value": f"0x{int(value):X}"})

    def on_unmapped(_uc_obj: Any, access: int, address: int, size: int, value: int, user_data: Any) -> bool:
        fault.update({
            "kind": str(user_data),
            "addr": f"0x{address:X}",
            "size": int(size),
            "pc": f"0x{int(uc.reg_read(ids[pc_name])):X}",
        })
        return False

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped, "execute")
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_unmapped, "read")
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped, "write")
    uc.hook_add(UC_HOOK_MEM_FETCH_PROT, on_unmapped, "execute")
    uc.hook_add(UC_HOOK_MEM_READ_PROT, on_unmapped, "read")
    uc.hook_add(UC_HOOK_MEM_WRITE_PROT, on_unmapped, "write")
    try:
        uc.emu_start(entry_pc, 0, count=max_steps)
        if not stop_reason:
            stop_reason = "instruction_limit" if steps >= max_steps else "stopped"
    except UcError as exc:
        stop_reason = "memory_fault" if fault else "emulation_error"
        detail = str(exc)
    else:
        detail = ""
    result = {
        "ok": stop_reason in {"return", "stopped"},
        "entry": f"0x{entry:X}",
        "architecture": {"name": arch, "bits": bits, "endian": endian},
        "steps": steps,
        "stop_reason": stop_reason,
        "trace": trace,
        "trace_truncated": steps > len(trace),
        "memory_writes": writes,
        "writes_truncated": write_limit > 0 and len(writes) >= write_limit,
        "patches_applied": patches_applied,
        "patches_failed": patches_failed,
        "hooks_applied": hooks_applied,
        "hooks_failed": hooks_failed,
        "observations": observations,
        "memory_after": _readback_memory(uc, mapped, arguments.get("readback") if isinstance(arguments, dict) else None),
        "registers": _get_registers(uc, ids),
        "mapped_pages": len(mapped),
    }
    if fault:
        result["fault"] = fault
        fault_addr = _int_value(fault.get("addr"))
        if fault_addr is not None and fault.get("kind") in {"read", "write", "execute"}:
            kind = str(fault.get("kind"))
            result["suggested_regions"] = [{
                "addr": f"0x{_align_down(fault_addr):X}",
                "size": PAGE_SIZE,
                "perm": "rx" if kind == "execute" else "rw" if kind == "write" else "r",
            }]
    if detail:
        result["detail"] = detail
    return result


def _replay_worker(conn: Any, snapshot: dict[str, Any], arguments: Any, max_steps: int, trace_limit: int, write_limit: int) -> None:
    try:
        conn.send(_emulate_once(snapshot, arguments, max_steps, trace_limit, write_limit))
    except BaseException as exc:
        conn.send({"ok": False, "error": "Replay worker failed", "detail": repr(exc)})
    finally:
        conn.close()


def replay_snapshot(
    snapshot: dict[str, Any],
    arguments: Any = None,
    *,
    max_steps: int = DEFAULT_MAX_STEPS,
    timeout_sec: float = 10.0,
    trace_limit: int = DEFAULT_TRACE_LIMIT,
    write_limit: int = DEFAULT_WRITE_LIMIT,
) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        return {"ok": False, "error": "Replay snapshot must be an object"}
    max_steps = max(1, min(int(max_steps), 2_000_000))
    timeout_sec = max(0.1, min(float(timeout_sec), 120.0))
    trace_limit = max(0, min(int(trace_limit), 10_000))
    write_limit = max(0, min(int(write_limit), 5_000))
    try:
        context = mp.get_context("spawn")
    except ValueError:
        context = mp.get_context("forkserver")
    read_end, write_end = context.Pipe(duplex=False)
    process = context.Process(
        target=_replay_worker,
        args=(write_end, snapshot, arguments, max_steps, trace_limit, write_limit),
        name="ida-function-replay",
    )
    try:
        process.start()
    except Exception as exc:
        read_end.close()
        write_end.close()
        return {"ok": False, "error": "Unable to start replay worker", "detail": repr(exc)}
    write_end.close()
    deadline = time.monotonic() + timeout_sec
    result: dict[str, Any] | None = None
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if read_end.poll(min(0.05, remaining)):
                try:
                    value = read_end.recv()
                    result = value if isinstance(value, dict) else {"ok": False, "error": "Invalid replay result"}
                except (EOFError, OSError) as exc:
                    result = {"ok": False, "error": "Unable to read replay result", "detail": str(exc), "exit_code": process.exitcode}
                break
            if not process.is_alive():
                break
        if result is None and process.is_alive():
            process.terminate()
            process.join(2.0)
            if process.is_alive():
                process.kill()
                process.join(1.0)
            result = {"ok": False, "error": "Replay timed out", "stop_reason": "wall_timeout", "timeout_sec": timeout_sec}
        elif result is None:
            if read_end.poll(0.2):
                try:
                    value = read_end.recv()
                    result = value if isinstance(value, dict) else {"ok": False, "error": "Invalid replay result"}
                except (EOFError, OSError) as exc:
                    result = {"ok": False, "error": "Unable to read replay result", "detail": str(exc), "exit_code": process.exitcode}
            else:
                result = {"ok": False, "error": "Replay worker exited without a result", "exit_code": process.exitcode}
        process.join(1.0)
    finally:
        if process.is_alive():
            process.terminate()
            process.join(1.0)
        if process.is_alive():
            process.kill()
            process.join(1.0)
        read_end.close()
    return result if isinstance(result, dict) else {"ok": False, "error": "Invalid replay result"}
