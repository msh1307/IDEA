from __future__ import annotations

from collections import defaultdict
import json
import re
import struct
import time
from typing import Any, Callable

import ida_auto
import ida_bytes
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_loader
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

from .sync import idasync


PRIMITIVE_READERS: dict[str, tuple[int, str | None, Callable[[bytes], Any]]] = {
    "byte": (1, "<B", lambda data: struct.unpack("<B", data)[0]),
    "word": (2, "<H", lambda data: struct.unpack("<H", data)[0]),
    "dword": (4, "<I", lambda data: struct.unpack("<I", data)[0]),
    "qword": (8, "<Q", lambda data: struct.unpack("<Q", data)[0]),
    "i8": (1, "<b", lambda data: struct.unpack("<b", data)[0]),
    "u8": (1, "<B", lambda data: struct.unpack("<B", data)[0]),
    "i16": (2, "<h", lambda data: struct.unpack("<h", data)[0]),
    "u16": (2, "<H", lambda data: struct.unpack("<H", data)[0]),
    "i32": (4, "<i", lambda data: struct.unpack("<i", data)[0]),
    "u32": (4, "<I", lambda data: struct.unpack("<I", data)[0]),
    "i64": (8, "<q", lambda data: struct.unpack("<q", data)[0]),
    "u64": (8, "<Q", lambda data: struct.unpack("<Q", data)[0]),
}

_INT_CLASS_RE = re.compile(r"^(?P<sign>[iu])(?P<bits>8|16|32|64)(?P<endian>le|be)?$")


def _parse_ea(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise ValueError(f"Unsupported address value: {value!r}")
    text = value.strip()
    if not text:
        raise ValueError("Missing address")
    try:
        return int(text, 0)
    except ValueError:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, text)
        if ea == ida_idaapi.BADADDR:
            raise ValueError(f"Unable to resolve address or symbol: {text}") from None
        return ea


def _hex(ea: int) -> str:
    return f"0x{ea:X}"


def _json_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _tool_result(payload: Any, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": _json_text(payload)}],
        "structuredContent": payload,
        "isError": is_error,
    }


def _read_bytes_raw(ea: int, size: int) -> bytes:
    if size < 0:
        raise ValueError("size must be >= 0")
    data = ida_bytes.get_bytes(ea, size)
    if data is None:
        raise ValueError(f"Unable to read {size} bytes at {_hex(ea)}")
    return data


def _raw_bin_search(ea: int, max_ea: int, data: bytes, mask: bytes) -> int:
    if hasattr(ida_bytes, "find_bytes"):
        flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=mask, flags=flags)
    if hasattr(ida_bytes, "bin_search"):
        flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
        return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)
    raise RuntimeError("No binary search API available")


def _decode_insn_at(ea: int) -> ida_ua.insn_t | None:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None
    return insn


def _make_byte_searcher(pattern: str):
    tokens = pattern.strip().split()
    if not tokens:
        raise ValueError("Empty pattern")

    if hasattr(ida_bytes, "find_bytes"):
        normalized = " ".join("?" if token in {"??", "?"} else token for token in tokens)

        def searcher(ea: int, max_ea: int) -> int:
            return ida_bytes.find_bytes(normalized, ea, range_end=max_ea)

        return searcher

    raw = bytearray()
    mask = bytearray()
    for token in tokens:
        if token in {"??", "?"}:
            raw.append(0)
            mask.append(0)
            continue
        raw.append(int(token, 16))
        mask.append(0xFF)
    data = bytes(raw)
    mask_bytes = bytes(mask)

    def searcher(ea: int, max_ea: int) -> int:
        return _raw_bin_search(ea, max_ea, data, mask_bytes)

    return searcher


def _name_at(ea: int) -> str:
    return ida_name.get_name(ea) or ""


def _segment_name(ea: int) -> str:
    seg = ida_segment.getseg(ea)
    return ida_segment.get_segm_name(seg) if seg else ""


def _type_at(ea: int) -> str:
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        try:
            return tif._print()
        except Exception:
            return str(tif)
    return idc.get_type(ea) or ""


def _resolve_decl_target(arguments: dict[str, Any]) -> tuple[int, str]:
    symbol = str(arguments.get("symbol") or arguments.get("name") or "").strip()
    if symbol:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, symbol)
        if ea == ida_idaapi.BADADDR:
            raise ValueError(f"Unable to resolve symbol: {symbol}")
        return ea, symbol
    ea = _parse_ea(arguments.get("addr"))
    return ea, _name_at(ea)


def _refresh_decompiler(ea: int) -> None:
    if not ida_hexrays.init_hexrays_plugin():
        return
    func = idaapi.get_func(ea)
    if func is None:
        return
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            cfunc.refresh_func_ctext()
    except Exception:
        pass


def _decompile_cfunc(ea: int):
    func = idaapi.get_func(ea)
    if func is None:
        raise ValueError(f"No function found at {_hex(ea)}")
    start_ea = func.start_ea
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")
    cfunc = ida_hexrays.decompile(start_ea)
    if cfunc is None:
        raise RuntimeError(f"Decompilation failed for {_hex(start_ea)}")
    return func, cfunc


def _iter_swig_vector(vec):
    if vec is None:
        return
    try:
        for item in vec:
            yield item
        return
    except TypeError:
        pass
    size = None
    for attr in ("size", "__len__"):
        try:
            candidate = getattr(vec, attr)
            size = int(candidate() if callable(candidate) else candidate)
            break
        except Exception:
            continue
    if size is None:
        return
    for idx in range(size):
        try:
            yield vec[idx]
        except Exception:
            break


def _iter_eamap_entries(eamap):
    if eamap is None:
        return
    try:
        for ea, items in eamap.items():
            yield int(ea), items
        return
    except Exception:
        pass
    if not hasattr(ida_hexrays, "eamap_begin"):
        return
    try:
        iterator = ida_hexrays.eamap_begin(eamap)
        end = ida_hexrays.eamap_end(eamap)
        guard = 0
        while iterator != end and guard < 100000:
            yield int(ida_hexrays.eamap_first(iterator)), ida_hexrays.eamap_second(iterator)
            iterator = ida_hexrays.eamap_next(iterator)
            guard += 1
    except Exception:
        return


def _pseudocode_lines(cfunc) -> list[str]:
    lines = []
    for line in _iter_swig_vector(cfunc.get_pseudocode()):
        raw = getattr(line, "line", line)
        lines.append(ida_lines.tag_remove(str(raw or "")))
    return lines


def _decompile_line_map_payload(ea: int) -> dict[str, Any]:
    func, cfunc = _decompile_cfunc(ea)
    pseudocode_lines = _pseudocode_lines(cfunc)
    line_to_eas: dict[int, set[int]] = {idx + 1: set() for idx in range(len(pseudocode_lines))}
    ea_to_lines: dict[int, set[int]] = defaultdict(set)
    mapped_items = 0

    for item_ea, item_vec in _iter_eamap_entries(cfunc.get_eamap()):
        for citem in _iter_swig_vector(item_vec):
            try:
                _x, y = cfunc.find_item_coords(citem)
            except Exception:
                continue
            line_no = int(y) + 1
            if line_no < 1 or line_no > len(pseudocode_lines):
                continue
            line_to_eas.setdefault(line_no, set()).add(int(item_ea))
            ea_to_lines[int(item_ea)].add(line_no)
            mapped_items += 1

    line_entries = []
    for idx, text in enumerate(pseudocode_lines, start=1):
        eas = sorted(line_to_eas.get(idx, set()))
        line_entries.append(
            {
                "line_number": idx,
                "text": text,
                "addresses": [_hex(item_ea) for item_ea in eas],
            }
        )

    ea_entries = []
    for item_ea in sorted(ea_to_lines):
        line_nos = sorted(ea_to_lines[item_ea])
        line_text = [pseudocode_lines[line_no - 1] for line_no in line_nos if 1 <= line_no <= len(pseudocode_lines)]
        ea_entries.append(
            {
                "address": _hex(item_ea),
                "lines": line_nos,
                "line_text": line_text,
            }
        )

    return {
        "addr": _hex(func.start_ea),
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "mode": "decompile_line_map",
        "line_count": len(pseudocode_lines),
        "mapped_address_count": len(ea_entries),
        "mapped_item_count": mapped_items,
        "lines": line_entries,
        "ea_to_lines": ea_entries,
    }


def _function_summary(func) -> dict[str, Any]:
    start = func.start_ea
    end = func.end_ea
    return {
        "address": _hex(start),
        "name": ida_funcs.get_func_name(start) or "",
        "segment": _segment_name(start),
        "size": max(0, end - start),
        "prototype": idc.get_type(start) or "",
    }


def _enclosing_function_payload(ea: int) -> dict[str, Any]:
    func = idaapi.get_func(ea)
    if func is None:
        return {
            "found": False,
            "query_address": _hex(ea),
            "contains_query": False,
        }
    payload = _function_summary(func)
    payload.update(
        {
            "found": True,
            "query_address": _hex(ea),
            "contains_query": func.start_ea <= ea < func.end_ea,
            "offset": max(0, ea - func.start_ea),
            "end_address": _hex(func.end_ea),
            "frame_size": idc.get_frame_size(func.start_ea),
            "comment": idc.get_func_cmt(func.start_ea, 1) or idc.get_func_cmt(func.start_ea, 0) or "",
        }
    )
    return payload


def _disasm_function_payload(ea: int, max_instructions: int = 5000) -> dict[str, Any]:
    func = idaapi.get_func(ea)
    if func is None:
        raise ValueError(f"No function found at {_hex(ea)}")
    items: list[dict[str, Any]] = []
    for idx, item_ea in enumerate(idautils.FuncItems(func.start_ea)):
        if idx >= max_instructions:
            break
        line = ida_lines.generate_disasm_line(item_ea, 0)
        items.append({"address": _hex(item_ea), "text": ida_lines.tag_remove(line or "")})
    payload = _enclosing_function_payload(ea)
    payload["instructions"] = items
    payload["instruction_count"] = len(items)
    payload["truncated"] = len(items) >= max_instructions
    return payload


def _xref_summary(xref) -> dict[str, Any]:
    return {
        "from": _hex(xref.frm),
        "to": _hex(xref.to),
        "type": int(xref.type),
        "is_code": bool(getattr(xref, "iscode", False)),
        "user": bool(getattr(xref, "user", False)),
    }


def _collect_xrefs_to(ea: int, limit: int) -> dict[str, Any]:
    refs = []
    for idx, xref in enumerate(idautils.XrefsTo(ea, ida_xref.XREF_ALL)):
        if idx >= limit:
            break
        refs.append(_xref_summary(xref))
    return {"addr": _hex(ea), "items": refs, "count": len(refs)}


def _collect_xrefs_from(ea: int, limit: int) -> dict[str, Any]:
    refs = []
    for idx, xref in enumerate(idautils.XrefsFrom(ea, ida_xref.XREF_ALL)):
        if idx >= limit:
            break
        refs.append(_xref_summary(xref))
    return {"addr": _hex(ea), "items": refs, "count": len(refs)}


def _split_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        parts = []
        for line in value.replace(",", "\n").splitlines():
            item = line.strip()
            if item:
                parts.append(item)
        return parts
    if value is None:
        return []
    return [str(value).strip()] if str(value).strip() else []


def _disasm_window(ea: int, max_instructions: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    current = ea
    for idx in range(max_instructions):
        if current == ida_idaapi.BADADDR:
            break
        line = ida_lines.generate_disasm_line(current, 0)
        items.append({"address": _hex(current), "text": ida_lines.tag_remove(line or "")})
        next_ea = ida_bytes.next_head(current, ida_ida.inf_get_max_ea())
        if next_ea == ida_idaapi.BADADDR or next_ea <= current:
            break
        current = next_ea
    return items


def _type_exists(type_name: str) -> bool:
    tif = ida_typeinf.tinfo_t()
    return bool(tif.get_named_type(None, type_name))


def _parse_int_class(text: str) -> tuple[int, bool, str, str]:
    cleaned = str(text or "").strip().lower()
    match = _INT_CLASS_RE.match(cleaned)
    if not match:
        raise ValueError(f"Invalid integer class: {text}")
    bits = int(match.group("bits"))
    signed = match.group("sign") == "i"
    endian = match.group("endian") or "le"
    byte_order = "little" if endian == "le" else "big"
    normalized = f"{'i' if signed else 'u'}{bits}{endian}"
    return bits, signed, byte_order, normalized


def _stack_frame_members(func) -> list[dict[str, Any]]:
    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
        return []

    members: list[dict[str, Any]] = []
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    for udm in udt:
        if udm.is_gap():
            continue
        members.append(
            {
                "name": str(udm.name or ""),
                "offset": _hex(udm.offset // 8),
                "size": _hex(udm.size // 8),
                "type": str(udm.type),
            }
        )
    return members


def _parse_int_like(value: Any, field_name: str = "value") -> int:
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"Missing {field_name}")
    return int(text, 0)


def _resolve_type_info(type_name: str) -> ida_typeinf.tinfo_t:
    normalized = str(type_name or "").strip()
    if not normalized:
        raise ValueError("Missing type name")

    primitive_aliases = {
        "char": ida_typeinf.BTF_INT8,
        "signed char": ida_typeinf.BTF_INT8,
        "int8": ida_typeinf.BTF_INT8,
        "__int8": ida_typeinf.BTF_INT8,
        "int8_t": ida_typeinf.BTF_INT8,
        "byte": ida_typeinf.BTF_UINT8,
        "unsigned char": ida_typeinf.BTF_UINT8,
        "uint8": ida_typeinf.BTF_UINT8,
        "__uint8": ida_typeinf.BTF_UINT8,
        "uint8_t": ida_typeinf.BTF_UINT8,
        "short": ida_typeinf.BTF_INT16,
        "short int": ida_typeinf.BTF_INT16,
        "int16": ida_typeinf.BTF_INT16,
        "__int16": ida_typeinf.BTF_INT16,
        "int16_t": ida_typeinf.BTF_INT16,
        "word": ida_typeinf.BTF_UINT16,
        "unsigned short": ida_typeinf.BTF_UINT16,
        "uint16": ida_typeinf.BTF_UINT16,
        "__uint16": ida_typeinf.BTF_UINT16,
        "uint16_t": ida_typeinf.BTF_UINT16,
        "int": ida_typeinf.BTF_INT32,
        "long": ida_typeinf.BTF_INT32,
        "int32": ida_typeinf.BTF_INT32,
        "__int32": ida_typeinf.BTF_INT32,
        "int32_t": ida_typeinf.BTF_INT32,
        "dword": ida_typeinf.BTF_UINT32,
        "unsigned int": ida_typeinf.BTF_UINT32,
        "unsigned long": ida_typeinf.BTF_UINT32,
        "uint32": ida_typeinf.BTF_UINT32,
        "__uint32": ida_typeinf.BTF_UINT32,
        "uint32_t": ida_typeinf.BTF_UINT32,
        "long long": ida_typeinf.BTF_INT64,
        "int64": ida_typeinf.BTF_INT64,
        "__int64": ida_typeinf.BTF_INT64,
        "int64_t": ida_typeinf.BTF_INT64,
        "qword": ida_typeinf.BTF_UINT64,
        "uint64": ida_typeinf.BTF_UINT64,
        "__uint64": ida_typeinf.BTF_UINT64,
        "uint64_t": ida_typeinf.BTF_UINT64,
        "float": ida_typeinf.BTF_FLOAT,
        "double": ida_typeinf.BTF_DOUBLE,
        "bool": ida_typeinf.BTF_BOOL,
        "void": ida_typeinf.BTF_VOID,
    }
    primitive = primitive_aliases.get(normalized.lower())
    if primitive is not None:
        return ida_typeinf.tinfo_t(primitive)

    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, normalized):
        return tif

    try:
        parsed = ida_typeinf.tinfo_t(normalized)
        if parsed:
            return parsed
    except Exception:
        pass

    raise ValueError(f"Unable to resolve type: {normalized}")


def _read_display_value(ea: int, size: int, type_name: str = "") -> str:
    if size <= 0:
        return ""
    lowered = type_name.lower()
    if "char" in lowered or ida_bytes.is_strlit(ida_bytes.get_flags(ea)):
        try:
            stype = idc.get_str_type(ea)
            raw = idc.get_strlit_contents(ea, size, stype)
            if isinstance(raw, bytes):
                return raw.decode("utf-8", "replace")
            if isinstance(raw, str):
                return raw
        except Exception:
            pass

    data = _read_bytes_raw(ea, size)
    if size == 1:
        return hex(data[0])
    if size == 2:
        return hex(int.from_bytes(data, "little"))
    if size == 4:
        return hex(int.from_bytes(data, "little"))
    if size == 8:
        return hex(int.from_bytes(data, "little"))
    return data.hex()


def _ensure_list_of_dicts(value: Any, field_name: str) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    raise ValueError(f"{field_name} must be an object or list of objects")


def _primitive_create(ea: int, elem_type: str) -> bool:
    normalized = elem_type.lower()
    if normalized in {"byte", "u8", "i8"}:
        return bool(idc.create_byte(ea))
    if normalized in {"word", "u16", "i16"}:
        return bool(idc.create_word(ea))
    if normalized in {"dword", "u32", "i32"}:
        return bool(idc.create_dword(ea))
    if normalized in {"qword", "u64", "i64", "ptr"}:
        return bool(idc.create_qword(ea))
    return False


@idasync
def get_metadata(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    sha256_bytes = ida_nalt.retrieve_input_file_sha256() or b""
    procname = ""
    try:
        procname = ida_ida.inf_get_procname() or ""
    except Exception:
        info = getattr(idaapi, "get_inf_structure", lambda: None)()
        procname = getattr(info, "procname", "") if info is not None else ""
    return {
        "path": ida_nalt.get_input_file_path() or "",
        "module": ida_nalt.get_root_filename() or "",
        "idb_path": idc.get_idb_path() or "",
        "sha256": sha256_bytes.hex(),
        "image_base": _hex(idaapi.get_imagebase()),
        "min_ea": _hex(ida_ida.inf_get_min_ea()),
        "max_ea": _hex(ida_ida.inf_get_max_ea()),
        "ida_version": idaapi.get_kernel_version(),
        "processor": procname,
        "bitness": 64 if ida_ida.inf_is_64bit() else 32,
    }


@idasync
def inspect(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    include_decompile = bool(arguments.get("include_decompile", False))
    include_disasm = bool(arguments.get("include_disasm", False))
    include_line_map = bool(arguments.get("include_line_map", False))
    max_instructions = min(max(1, int(arguments.get("max_instructions", 200))), 4000)

    payload = inspect_addr({"addr": ea})
    if include_decompile:
        try:
            payload["decompile"] = decompile({"addr": ea, "fallback": arguments.get("fallback", "disasm")})
        except Exception as exc:
            payload["decompile_error"] = str(exc)
    if include_disasm:
        try:
            payload["disasm"] = disasm({"addr": ea, "max_instructions": max_instructions})
        except Exception as exc:
            payload["disasm_error"] = str(exc)
    if include_line_map:
        try:
            payload["line_map"] = get_decompile_line_map({"addr": ea})
        except Exception as exc:
            payload["line_map_error"] = str(exc)
    return payload


@idasync
def list_segments(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    results = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        results.append(
            {
                "name": ida_segment.get_segm_name(seg),
                "start": _hex(seg.start_ea),
                "end": _hex(seg.end_ea),
                "size": max(0, seg.end_ea - seg.start_ea),
                "perm": int(seg.perm),
            }
        )
    return results


@idasync
def list_globals(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    offset = max(0, int(arguments.get("offset", 0)))
    count = max(0, int(arguments.get("count", 100)))
    filt = str(arguments.get("filter", "") or "").lower()
    items = []
    for ea, name in idautils.Names():
        if not name or idaapi.get_func(ea) is not None:
            continue
        if filt and filt not in name.lower() and filt not in _hex(ea).lower():
            continue
        items.append(
            {
                "address": _hex(ea),
                "name": name,
                "segment": _segment_name(ea),
                "type": _type_at(ea),
                "size": ida_bytes.get_item_size(ea),
            }
        )
    total = len(items)
    sliced = items[offset:] if count == 0 else items[offset : offset + count]
    return {"items": sliced, "offset": offset, "count": count, "total": total}


@idasync
def imports(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    offset = max(0, int(arguments.get("offset", 0)))
    count = max(0, int(arguments.get("count", 100)))
    filt = str(arguments.get("filter", "") or "").lower()
    items = []
    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal):
            imported_name = symbol_name or f"#{ordinal}"
            if filt and filt not in imported_name.lower() and filt not in module_name.lower():
                return True
            items.append(
                {
                    "address": _hex(ea),
                    "imported_name": imported_name,
                    "module": module_name,
                }
            )
            return True

        ida_nalt.enum_import_names(i, imp_cb)

    total = len(items)
    sliced = items[offset:] if count == 0 else items[offset : offset + count]
    return {"items": sliced, "offset": offset, "count": count, "total": total}


@idasync
def analysis_status(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    auto_is_ok = False
    if hasattr(ida_auto, "auto_is_ok"):
        try:
            auto_is_ok = bool(ida_auto.auto_is_ok())
        except Exception:
            auto_is_ok = False
    function_total = sum(1 for _ in idautils.Functions())
    return {
        "autoanalysis_complete": auto_is_ok,
        "function_total": function_total,
    }


@idasync
def wait_for_autoanalysis(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    timeout_sec = max(0.0, float(arguments.get("timeout_sec", 120.0)))
    poll_interval = max(0.05, min(float(arguments.get("poll_interval_sec", 0.25)), 2.0))
    start = time.monotonic()
    if hasattr(ida_auto, "auto_wait"):
        ida_auto.auto_wait()
    while True:
        ready = False
        if hasattr(ida_auto, "auto_is_ok"):
            try:
                ready = bool(ida_auto.auto_is_ok())
            except Exception:
                ready = False
        if ready:
            break
        if timeout_sec and (time.monotonic() - start) >= timeout_sec:
            break
        time.sleep(poll_interval)
    function_total = sum(1 for _ in idautils.Functions())
    return {
        "autoanalysis_complete": bool(getattr(ida_auto, "auto_is_ok", lambda: True)()),
        "function_total": function_total,
        "waited_sec": round(time.monotonic() - start, 3),
    }


@idasync
def list_functions(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    offset = max(0, int(arguments.get("offset", 0)))
    count = max(0, int(arguments.get("count", 100)))
    filt = str(arguments.get("filter", "") or "").lower()
    include_extern = bool(arguments.get("include_extern", False))
    include_thunks = bool(arguments.get("include_thunks", False))
    functions = []
    for ea in idautils.Functions():
        func = idaapi.get_func(ea)
        if func is None:
            continue
        item = _function_summary(func)
        if not include_extern and item["segment"].lower() == "extern":
            continue
        flags = idc.get_func_flags(func.start_ea)
        if not include_thunks and flags != -1 and (flags & idc.FUNC_THUNK):
            continue
        if filt and filt not in item["name"].lower() and filt not in item["address"].lower():
            continue
        functions.append(item)
    functions.sort(key=lambda item: (item["segment"].lower() == "extern", item["address"]))
    total = len(functions)
    if count == 0:
        sliced = functions[offset:]
    else:
        sliced = functions[offset : offset + count]
    return {
        "items": sliced,
        "offset": offset,
        "count": count,
        "total": total,
        "include_extern": include_extern,
        "include_thunks": include_thunks,
    }


@idasync
def lookup_funcs(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    queries = _split_string_list(arguments.get("queries", []))
    if not queries:
        raise ValueError("queries must be a string or list of strings")
    results = []
    all_funcs = [idaapi.get_func(ea) for ea in idautils.Functions()]
    for query in queries:
        matches = []
        try:
            ea = _parse_ea(query)
            func = idaapi.get_func(ea)
            if func is not None:
                matches.append(_function_summary(func))
        except Exception:
            q = str(query).lower()
            for func in all_funcs:
                if func is None:
                    continue
                summary = _function_summary(func)
                if q in summary["name"].lower():
                    matches.append(summary)
                    if len(matches) >= 20:
                        break
        results.append({"query": query, "matches": matches})
    return results


@idasync
def get_function(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    func = idaapi.get_func(ea)
    if func is None:
        return {
            "found": False,
            "address": _hex(ea),
            "name": "",
            "segment": _segment_name(ea),
            "size": 0,
            "prototype": "",
            "frame_size": 0,
            "comment": "",
            "error": f"No function found at {_hex(ea)}",
        }
    summary = _function_summary(func)
    summary["frame_size"] = idc.get_frame_size(func.start_ea)
    summary["comment"] = idc.get_func_cmt(func.start_ea, 1) or idc.get_func_cmt(func.start_ea, 0) or ""
    summary["found"] = True
    return summary


@idasync
def get_enclosing_function(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    return _enclosing_function_payload(ea)


@idasync
def decompile(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    func = idaapi.get_func(ea)
    fallback = str(arguments.get("fallback") or "disasm").strip().lower()
    if func is None:
        if fallback not in {"disasm", "asm"}:
            raise ValueError(f"No function found at {_hex(ea)}")
        return {
            "addr": _hex(ea),
            "name": "",
            "mode": "disasm",
            "decompile_error": f"No function found at {_hex(ea)}",
            "instructions": _disasm_window(ea, min(max(1, int(arguments.get('max_instructions', 200))), 2000)),
        }
    start_ea = func.start_ea
    name = ida_funcs.get_func_name(start_ea) or ""
    try:
        _func, cfunc = _decompile_cfunc(start_ea)
        return {"addr": _hex(start_ea), "name": name, "mode": "decompile", "code": str(cfunc)}
    except Exception as exc:
        if fallback not in {"disasm", "asm"}:
            raise
        instructions = []
        for idx, item_ea in enumerate(idautils.FuncItems(start_ea)):
            if idx >= 4000:
                break
            line = ida_lines.generate_disasm_line(item_ea, 0)
            instructions.append({"address": _hex(item_ea), "text": ida_lines.tag_remove(line or "")})
        return {
            "addr": _hex(start_ea),
            "name": name,
            "mode": "disasm",
            "decompile_error": str(exc),
            "instructions": instructions,
        }


@idasync
def get_decompile_line_map(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    return _decompile_line_map_payload(ea)


@idasync
def disasm_function(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    max_instructions = min(max(1, int(arguments.get("max_instructions", 4000))), 20000)
    return _disasm_function_payload(ea, max_instructions=max_instructions)


@idasync
def disasm(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    max_instructions = min(max(1, int(arguments.get("max_instructions", 400))), 5000)
    func = idaapi.get_func(ea)
    items: list[dict[str, Any]] = []
    if func is not None:
        iterable = idautils.FuncItems(func.start_ea)
    else:
        iterable = []
        current = ea
        for _ in range(max_instructions):
            iterable.append(current)
            next_ea = ida_bytes.next_head(current, ida_ida.inf_get_max_ea())
            if next_ea == ida_idaapi.BADADDR or next_ea <= current:
                break
            current = next_ea
    for idx, item_ea in enumerate(iterable):
        if idx >= max_instructions:
            break
        line = ida_lines.generate_disasm_line(item_ea, 0)
        items.append({"address": _hex(item_ea), "text": ida_lines.tag_remove(line or "")})
    return {"addr": _hex(func.start_ea) if func else _hex(ea), "instructions": items}


@idasync
def inspect_addr(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    flags = ida_bytes.get_flags(ea)
    item_size = ida_bytes.get_item_size(ea)
    prev_head = ida_bytes.prev_head(ea, ida_ida.inf_get_min_ea())
    next_head = ida_bytes.next_head(ea, ida_ida.inf_get_max_ea())
    payload = get_data_item({"addr": ea})
    payload.update(
        {
            "query_address": _hex(ea),
            "is_code": bool(ida_bytes.is_code(flags)),
            "is_data": bool(ida_bytes.is_data(flags)),
            "is_unknown": bool(ida_bytes.is_unknown(flags)),
            "is_tail": bool(ida_bytes.is_tail(flags)),
            "item_size": item_size,
            "prev_head": _hex(prev_head) if prev_head != ida_idaapi.BADADDR else "",
            "next_head": _hex(next_head) if next_head != ida_idaapi.BADADDR else "",
            "enclosing_function": _enclosing_function_payload(ea),
        }
    )
    return payload


@idasync
def get_xrefs_to(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    limit = max(1, int(arguments.get("limit", 200)))
    return _collect_xrefs_to(ea, limit)


@idasync
def get_xrefs_from(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    limit = max(1, int(arguments.get("limit", 200)))
    return _collect_xrefs_from(ea, limit)


@idasync
def xrefs_to(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    addrs = _split_string_list(arguments.get("addrs", []))
    if not addrs:
        raise ValueError("addrs must be a string or list of strings")
    limit = max(1, int(arguments.get("limit", 100)))
    return [_collect_xrefs_to(_parse_ea(addr), limit) for addr in addrs]


@idasync
def callees(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    addrs = _split_string_list(arguments.get("addrs", arguments.get("addr", [])))
    if not addrs:
        raise ValueError("addr or addrs is required")
    limit = max(1, min(int(arguments.get("limit", 200)), 500))
    results = []

    for query in addrs:
        ea = _parse_ea(query)
        func = idaapi.get_func(ea)
        if func is None:
            results.append({"addr": query, "callees": [], "error": "No function found"})
            continue

        seen: dict[int, dict[str, Any]] = {}
        more = False
        for item_ea in idautils.FuncItems(func.start_ea):
            insn = _decode_insn_at(item_ea)
            if insn is None:
                continue
            if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                continue
            op0 = insn.ops[0]
            target = None
            if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                target = int(op0.addr)
            elif op0.type == ida_ua.o_imm:
                target = int(op0.value)
            if target is None or target in seen:
                continue
            seen[target] = {
                "address": _hex(target),
                "name": _name_at(target),
                "type": "internal" if idaapi.get_func(target) is not None else "external",
            }
            if len(seen) >= limit:
                more = True
                break
        results.append({"addr": _hex(func.start_ea), "callees": list(seen.values()), "more": more})
    return results


@idasync
def basic_blocks(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    addrs = _split_string_list(arguments.get("addrs", arguments.get("addr", [])))
    if not addrs:
        raise ValueError("addr or addrs is required")
    max_blocks = max(1, min(int(arguments.get("max_blocks", 1000)), 10000))
    offset = max(0, int(arguments.get("offset", 0)))
    results = []

    for query in addrs:
        ea = _parse_ea(query)
        func = idaapi.get_func(ea)
        if func is None:
            results.append({"addr": query, "blocks": [], "count": 0, "error": "Function not found"})
            continue
        blocks = []
        for block in idaapi.FlowChart(func):
            blocks.append(
                {
                    "start": _hex(block.start_ea),
                    "end": _hex(block.end_ea),
                    "size": max(0, block.end_ea - block.start_ea),
                    "type": int(block.type),
                    "successors": [_hex(succ.start_ea) for succ in block.succs()],
                    "predecessors": [_hex(pred.start_ea) for pred in block.preds()],
                }
            )
        total = len(blocks)
        sliced = blocks[offset : offset + max_blocks]
        results.append(
            {
                "addr": _hex(func.start_ea),
                "blocks": sliced,
                "count": len(sliced),
                "total_blocks": total,
                "cursor": {"next": offset + max_blocks} if offset + max_blocks < total else {"done": True},
                "error": None,
            }
        )
    return results


@idasync
def xrefs_to_field(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    queries = arguments.get("queries", arguments)
    if isinstance(queries, dict):
        queries = [queries]
    if not isinstance(queries, list):
        raise ValueError("queries must be an object or list of objects")

    results = []
    for query in queries:
        struct_name = str(query.get("struct") or query.get("struct_name") or "").strip()
        field_name = str(query.get("field") or query.get("field_name") or "").strip()
        if not struct_name or not field_name:
            raise ValueError("struct and field are required")

        try:
            tif = _resolve_type_info(struct_name)
            if not tif.is_udt():
                raise ValueError(f"{struct_name} is not a struct/union type")

            idx = -1
            if hasattr(ida_typeinf, "get_udm_by_fullname"):
                idx = int(ida_typeinf.get_udm_by_fullname(None, f"{struct_name}.{field_name}"))
            if idx < 0:
                udt = ida_typeinf.udt_type_data_t()
                tif.get_udt_details(udt)
                for candidate_idx, udm in enumerate(udt):
                    if not udm.is_gap() and str(udm.name or "") == field_name:
                        idx = candidate_idx
                        break
            if idx < 0:
                raise ValueError(f"Field not found: {struct_name}.{field_name}")

            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                raise ValueError(f"Unable to resolve field tid for {struct_name}.{field_name}")

            refs = []
            for xref in idautils.XrefsTo(tid):
                refs.append(
                    {
                        "address": _hex(xref.frm),
                        "type": "code" if getattr(xref, "iscode", False) else "data",
                        "function": ida_funcs.get_func_name(xref.frm) or "",
                    }
                )
            results.append({"struct": struct_name, "field": field_name, "xrefs": refs, "count": len(refs)})
        except Exception as exc:
            results.append({"struct": struct_name, "field": field_name, "xrefs": [], "count": 0, "error": str(exc)})

    return results


@idasync
def list_strings(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    offset = max(0, int(arguments.get("offset", 0)))
    count = max(0, int(arguments.get("count", 100)))
    filt = str(arguments.get("filter", "") or "").lower()
    strings = idautils.Strings()
    items = []
    for string in strings:
        value = str(string)
        if filt and filt not in value.lower():
            continue
        items.append(
            {
                "address": _hex(string.ea),
                "length": int(string.length),
                "type": int(string.strtype),
                "value": value,
            }
        )
    total = len(items)
    if count == 0:
        sliced = items[offset:]
    else:
        sliced = items[offset : offset + count]
    return {"items": sliced, "offset": offset, "count": count, "total": total}


@idasync
def find_bytes(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    patterns = arguments.get("patterns", arguments.get("pattern", []))
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(patterns, list) or not patterns:
        raise ValueError("patterns must be a string or non-empty list of strings")
    limit = max(1, min(int(arguments.get("limit", 100)), 10000))
    offset = max(0, int(arguments.get("offset", 0)))
    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()
    results: list[dict[str, Any]] = []

    for pattern in patterns:
        pattern_text = str(pattern or "").strip()
        if not pattern_text:
            results.append({"pattern": pattern, "matches": [], "count": 0, "truncated": False, "error": "Empty pattern"})
            continue
        try:
            searcher = _make_byte_searcher(pattern_text)
            matches = []
            skipped = 0
            more = False
            ea = min_ea
            while ea != ida_idaapi.BADADDR:
                ea = searcher(ea, max_ea)
                if ea == ida_idaapi.BADADDR:
                    break
                if skipped < offset:
                    skipped += 1
                else:
                    matches.append({"address": _hex(ea), "segment": _segment_name(ea), "name": _name_at(ea)})
                    if len(matches) >= limit:
                        next_ea = searcher(ea + 1, max_ea)
                        more = next_ea != ida_idaapi.BADADDR
                        break
                ea += 1
            results.append({"pattern": pattern_text, "matches": matches, "count": len(matches), "truncated": more})
        except Exception as exc:
            results.append({"pattern": pattern_text, "matches": [], "count": 0, "truncated": False, "error": str(exc)})
    return results


@idasync
def find_text(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    query = str(arguments.get("query") or arguments.get("text") or arguments.get("needle") or "").strip()
    if not query:
        raise ValueError("query is required")
    kinds = arguments.get("kinds", ["strings", "names"])
    if isinstance(kinds, str):
        kinds = [item.strip() for item in kinds.split(",") if item.strip()]
    if not isinstance(kinds, list) or not kinds:
        raise ValueError("kinds must be a string or non-empty list")
    limit = max(1, min(int(arguments.get("limit", 100)), 10000))
    offset = max(0, int(arguments.get("offset", 0)))
    query_lower = query.lower()
    normalized_kinds = {str(kind).strip().lower() for kind in kinds}
    matches: list[dict[str, Any]] = []

    def append_match(kind: str, ea: int, text: str, *, extra: dict[str, Any] | None = None) -> None:
        entry = {
            "kind": kind,
            "address": _hex(ea),
            "segment": _segment_name(ea),
            "name": _name_at(ea),
            "text": text,
        }
        if extra:
            entry.update(extra)
        matches.append(entry)

    if "strings" in normalized_kinds:
        for string in idautils.Strings():
            value = str(string)
            if query_lower in value.lower():
                append_match("string", string.ea, value, extra={"length": int(string.length), "strtype": int(string.strtype)})

    if "names" in normalized_kinds:
        for ea, name in idautils.Names():
            if query_lower in name.lower():
                append_match("name", ea, name)

    if "comments" in normalized_kinds:
        max_ea = ida_ida.inf_get_max_ea()
        current = ida_ida.inf_get_min_ea()
        while current != ida_idaapi.BADADDR and current < max_ea:
            regular = idc.get_cmt(current, 0) or ""
            repeatable = idc.get_cmt(current, 1) or ""
            if regular and query_lower in regular.lower():
                append_match("comment", current, regular, extra={"repeatable": False})
            if repeatable and query_lower in repeatable.lower():
                append_match("comment", current, repeatable, extra={"repeatable": True})
            next_ea = ida_bytes.next_head(current, max_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea <= current:
                break
            current = next_ea

    if "disasm" in normalized_kinds:
        max_ea = ida_ida.inf_get_max_ea()
        current = ida_ida.inf_get_min_ea()
        while current != ida_idaapi.BADADDR and current < max_ea:
            line = ida_lines.tag_remove(ida_lines.generate_disasm_line(current, 0) or "")
            if line and query_lower in line.lower():
                append_match("disasm", current, line)
            next_ea = ida_bytes.next_head(current, max_ea)
            if next_ea == ida_idaapi.BADADDR or next_ea <= current:
                break
            current = next_ea

    total = len(matches)
    sliced = matches[offset : offset + limit]
    return {"query": query, "kinds": sorted(normalized_kinds), "items": sliced, "offset": offset, "count": len(sliced), "total": total, "truncated": offset + len(sliced) < total}


@idasync
def find_regex(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    pattern = str(arguments.get("pattern") or "").strip()
    if not pattern:
        raise ValueError("pattern is required")
    limit = max(1, min(int(arguments.get("limit", 30)), 500))
    offset = max(0, int(arguments.get("offset", 0)))
    regex = re.compile(pattern, re.IGNORECASE)

    matches = []
    skipped = 0
    more = False
    for string in idautils.Strings():
        value = str(string)
        if not regex.search(value):
            continue
        if skipped < offset:
            skipped += 1
            continue
        if len(matches) >= limit:
            more = True
            break
        matches.append({"address": _hex(string.ea), "string": value})
    return {
        "pattern": pattern,
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


@idasync
def find_immediates(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    values = arguments.get("values", arguments.get("value", []))
    if isinstance(values, (str, int)):
        values = [values]
    if not isinstance(values, list) or not values:
        raise ValueError("values must be an int/string or non-empty list")
    limit = max(1, min(int(arguments.get("limit", 100)), 10000))
    offset = max(0, int(arguments.get("offset", 0)))
    results: list[dict[str, Any]] = []
    exec_segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is not None and (seg.perm & idaapi.SEGPERM_EXEC):
            exec_segments.append(seg)

    for raw_value in values:
        value = raw_value
        if isinstance(value, str):
            value = int(value, 0)
        if not isinstance(value, int):
            raise ValueError(f"Unsupported immediate value: {raw_value!r}")
        matches = []
        skipped = 0
        more = False
        seen: set[int] = set()
        for seg in exec_segments:
            current = seg.start_ea
            while current != ida_idaapi.BADADDR and current < seg.end_ea:
                insn = _decode_insn_at(current)
                if insn is not None:
                    matched = False
                    for op in insn.ops:
                        if op.type == ida_ua.o_void:
                            break
                        if op.type != ida_ua.o_imm:
                            continue
                        if int(op.value) != value:
                            continue
                        if current in seen:
                            matched = True
                            break
                        seen.add(current)
                        line = ida_lines.tag_remove(ida_lines.generate_disasm_line(current, 0) or "")
                        if skipped < offset:
                            skipped += 1
                        else:
                            matches.append({"address": _hex(current), "segment": _segment_name(current), "text": line, "function": ida_funcs.get_func_name(current) or ""})
                            if len(matches) >= limit:
                                more = True
                                matched = True
                                break
                        matched = True
                        break
                    if more:
                        break
                next_ea = ida_bytes.next_head(current, seg.end_ea)
                if next_ea == ida_idaapi.BADADDR or next_ea <= current:
                    break
                current = next_ea
            if more:
                break
        results.append({"value": value, "matches": matches, "count": len(matches), "truncated": more})
    return results


@idasync
def find_insns(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    sequences = arguments.get("sequences", arguments.get("sequence", []))
    if isinstance(sequences, str):
        sequences = [sequences]
    if not isinstance(sequences, list) or not sequences:
        raise ValueError("sequences must be a string or non-empty list of strings")
    limit = max(1, min(int(arguments.get("limit", 100)), 10000))
    offset = max(0, int(arguments.get("offset", 0)))
    results: list[dict[str, Any]] = []

    prepared_sequences = []
    for sequence in sequences:
        parts = [part.strip().lower() for part in str(sequence or "").split(";") if part.strip()]
        if not parts:
            results.append({"sequence": sequence, "matches": [], "count": 0, "truncated": False, "error": "Empty sequence"})
            continue
        prepared_sequences.append((str(sequence), parts))

    all_heads = []
    max_ea = ida_ida.inf_get_max_ea()
    current = ida_ida.inf_get_min_ea()
    while current != ida_idaapi.BADADDR and current < max_ea:
        all_heads.append(current)
        next_ea = ida_bytes.next_head(current, max_ea)
        if next_ea == ida_idaapi.BADADDR or next_ea <= current:
            break
        current = next_ea

    for sequence_text, parts in prepared_sequences:
        matches = []
        skipped = 0
        more = False
        for head in all_heads:
            cursor = head
            matched_lines: list[str] = []
            found = True
            for part in parts:
                line = ida_lines.tag_remove(ida_lines.generate_disasm_line(cursor, 0) or "")
                if not line or part not in line.lower():
                    found = False
                    break
                matched_lines.append(line)
                next_ea = ida_bytes.next_head(cursor, max_ea)
                if next_ea == ida_idaapi.BADADDR or next_ea <= cursor:
                    cursor = next_ea
                else:
                    cursor = next_ea
            if not found:
                continue
            if skipped < offset:
                skipped += 1
                continue
            matches.append({"address": _hex(head), "segment": _segment_name(head), "function": ida_funcs.get_func_name(head) or "", "lines": matched_lines})
            if len(matches) >= limit:
                more = True
                break
        results.append({"sequence": sequence_text, "matches": matches, "count": len(matches), "truncated": more})
    return results


@idasync
def search(arguments: dict[str, Any] | None = None) -> Any:
    arguments = arguments or {}
    kind = str(arguments.get("kind") or "text").strip().lower()
    if kind == "text":
        payload = dict(arguments)
        if "query" not in payload:
            payload["query"] = arguments.get("q", "")
        return find_text(payload)
    if kind == "regex":
        payload = dict(arguments)
        if "pattern" not in payload:
            payload["pattern"] = arguments.get("query") or arguments.get("q") or ""
        return find_regex(payload)
    if kind in {"bytes", "byte"}:
        payload = dict(arguments)
        if "pattern" not in payload and "patterns" not in payload:
            payload["pattern"] = arguments.get("query") or arguments.get("q") or ""
        return find_bytes(payload)
    if kind in {"imm", "immediate", "immediates"}:
        payload = dict(arguments)
        if "value" not in payload and "values" not in payload:
            payload["value"] = arguments.get("query") or arguments.get("q")
        return find_immediates(payload)
    if kind in {"insn", "insns", "instruction"}:
        payload = dict(arguments)
        if "sequence" not in payload and "sequences" not in payload:
            payload["sequence"] = arguments.get("query") or arguments.get("q") or ""
        return find_insns(payload)
    raise ValueError(f"Unsupported search kind: {kind}")


@idasync
def read_bytes(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    size = int(arguments.get("size", 0))
    data = _read_bytes_raw(ea, size)
    return {"addr": _hex(ea), "size": size, "hex": data.hex(), "bytes": list(data)}


@idasync
def get_bytes(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    regions = arguments.get("regions", arguments)
    if isinstance(regions, dict):
        regions = [regions]
    if not isinstance(regions, list):
        raise ValueError("regions must be an object or list of objects")
    results = []
    for item in regions:
        ea = _parse_ea(item.get("addr"))
        size = int(item.get("size", 0))
        data = _read_bytes_raw(ea, size)
        results.append({"addr": _hex(ea), "data": " ".join(f"0x{byte:02x}" for byte in data), "size": size})
    return results


def _typed_read(arguments: dict[str, Any] | None, kind: str) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    size, _fmt, unpacker = PRIMITIVE_READERS[kind]
    data = _read_bytes_raw(ea, size)
    return {"addr": _hex(ea), "type": kind, "size": size, "value": unpacker(data), "hex": data.hex()}


@idasync
def get_int(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    queries = arguments.get("queries", arguments)
    if isinstance(queries, dict):
        queries = [queries]
    if not isinstance(queries, list):
        raise ValueError("queries must be an object or list of objects")
    results = []
    for item in queries:
        ea = _parse_ea(item.get("addr"))
        bits, signed, byte_order, normalized = _parse_int_class(item.get("ty"))
        size = bits // 8
        data = _read_bytes_raw(ea, size)
        results.append(
            {
                "addr": _hex(ea),
                "ty": normalized,
                "value": int.from_bytes(data, byte_order, signed=signed),
                "hex": data.hex(),
            }
        )
    return results


@idasync
def get_string(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    addrs = _split_string_list(arguments.get("addrs", arguments.get("addr", [])))
    if not addrs:
        raise ValueError("addr or addrs is required")
    results = []
    for query in addrs:
        ea = _parse_ea(query)
        stype = idc.get_str_type(ea)
        raw = idc.get_strlit_contents(ea, -1, stype)
        if isinstance(raw, bytes):
            value = raw.decode("utf-8", "replace")
        elif isinstance(raw, str):
            value = raw
        else:
            value = ""
        if not value:
            value = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")
        results.append({"addr": _hex(ea), "value": value})
    return results


@idasync
def get_global_value(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    queries = _split_string_list(arguments.get("queries", arguments.get("query", [])))
    if not queries:
        queries = _split_string_list(arguments.get("addr", []))
    if not queries:
        raise ValueError("query/queries or addr is required")

    results = []
    for query in queries:
        try:
            ea = _parse_ea(query)
            type_name = _type_at(ea)
            size = ida_bytes.get_item_size(ea)
            if not size and type_name:
                try:
                    size = max(0, int(_resolve_type_info(type_name).get_size()))
                except Exception:
                    size = 0
            value = _read_display_value(ea, size, type_name)
            results.append(
                {
                    "query": query,
                    "address": _hex(ea),
                    "name": _name_at(ea),
                    "type": type_name,
                    "size": size,
                    "value": value,
                    "error": None,
                }
            )
        except Exception as exc:
            results.append({"query": query, "value": None, "error": str(exc)})
    return results


@idasync
def read(arguments: dict[str, Any] | None = None) -> Any:
    arguments = arguments or {}
    kind = str(arguments.get("kind") or "bytes").strip().lower()
    if kind == "bytes":
        return read_bytes(arguments)
    if kind in {"byte", "word", "dword", "qword"}:
        return _typed_read(arguments, kind)
    if kind in {"int", "integer"}:
        return get_int({"queries": arguments.get("queries", [arguments])})
    if kind == "string":
        return get_string(arguments)
    if kind == "struct":
        return read_struct(arguments)
    if kind == "array":
        return read_array(arguments)
    if kind in {"global", "global_value"}:
        return get_global_value(arguments)
    if kind in {"hex", "dump", "hex_dump"}:
        return hex_dump(arguments)
    raise ValueError(f"Unsupported read kind: {kind}")


@idasync
def read_byte(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return _typed_read(arguments, "byte")


@idasync
def read_word(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return _typed_read(arguments, "word")


@idasync
def read_dword(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return _typed_read(arguments, "dword")


@idasync
def read_qword(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return _typed_read(arguments, "qword")


@idasync
def read_array(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    elem_type = str(arguments.get("elem_type", "byte") or "byte").lower()
    count = max(0, int(arguments.get("count", 0)))
    items = []
    if elem_type in PRIMITIVE_READERS:
        elem_size, _fmt, unpacker = PRIMITIVE_READERS[elem_type]
        for idx in range(count):
            current = ea + idx * elem_size
            data = _read_bytes_raw(current, elem_size)
            items.append({"index": idx, "addr": _hex(current), "value": unpacker(data), "hex": data.hex()})
        return {"addr": _hex(ea), "elem_type": elem_type, "count": count, "items": items}

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, elem_type):
        raise ValueError(f"Unsupported elem_type: {elem_type}")
    elem_size = tif.get_size()
    if elem_size <= 0:
        raise ValueError(f"Unable to determine size for type: {elem_type}")
    for idx in range(count):
        current = ea + idx * elem_size
        data = _read_bytes_raw(current, elem_size)
        items.append({"index": idx, "addr": _hex(current), "size": elem_size, "hex": data.hex()})
    return {"addr": _hex(ea), "elem_type": elem_type, "count": count, "items": items}


@idasync
def hex_dump(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    size = int(arguments.get("size", 0))
    width = max(1, int(arguments.get("width", 16)))
    data = _read_bytes_raw(ea, size)
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{ea + offset:08X}  {hex_part:<{width * 3}}  {ascii_part}")
    return {"addr": _hex(ea), "size": size, "width": width, "text": "\n".join(lines)}


@idasync
def read_struct(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    struct_name = str(arguments.get("struct_name") or arguments.get("name") or "").strip()

    if struct_name:
        tif = _resolve_type_info(struct_name)
    else:
        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, ea):
            raise ValueError(f"No type information at {_hex(ea)} and no struct_name provided")
        struct_name = tif.get_type_name() or _type_at(ea) or "<anonymous>"

    if not tif.is_udt():
        raise ValueError(f"{struct_name} is not a struct/union type")

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        raise ValueError(f"Unable to enumerate fields for {struct_name}")

    members = []
    for udm in udt:
        if udm.is_gap():
            continue
        offset = udm.offset // 8
        size = max(0, udm.size // 8)
        member_ea = ea + offset
        member_type = str(udm.type)
        item = {
            "name": str(udm.name or ""),
            "offset": _hex(offset),
            "address": _hex(member_ea),
            "size": size,
            "type": member_type,
            "bytes": _read_bytes_raw(member_ea, size).hex() if size > 0 else "",
            "value": _read_display_value(member_ea, size, member_type),
        }
        members.append(item)

    return {
        "address": _hex(ea),
        "struct_name": struct_name,
        "size": max(0, tif.get_size()),
        "member_count": len(members),
        "members": members,
    }


@idasync
def xrefs(arguments: dict[str, Any] | None = None) -> Any:
    arguments = arguments or {}
    direction = str(arguments.get("direction") or "to").strip().lower()
    if arguments.get("struct") or arguments.get("struct_name"):
        return xrefs_to_field(arguments)
    if direction == "to":
        if arguments.get("addrs") is not None:
            return xrefs_to(arguments)
        return get_xrefs_to(arguments)
    if direction == "from":
        if arguments.get("addrs") is not None:
            addrs = _split_string_list(arguments.get("addrs"))
            limit = max(1, int(arguments.get("limit", 100)))
            return [get_xrefs_from({"addr": addr, "limit": limit}) for addr in addrs]
        return get_xrefs_from(arguments)
    raise ValueError(f"Unsupported xref direction: {direction}")


@idasync
def stack_frame(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    addrs = _split_string_list(arguments.get("addrs", arguments.get("addr", [])))
    if not addrs:
        raise ValueError("addr or addrs is required")
    results = []
    for query in addrs:
        ea = _parse_ea(query)
        func = idaapi.get_func(ea)
        if func is None:
            results.append({"addr": query, "vars": None, "error": "No function found"})
            continue
        frame_tif = ida_typeinf.tinfo_t()
        ida_frame.get_func_frame(frame_tif, func)
        results.append({"addr": _hex(func.start_ea), "vars": _stack_frame_members(func)})
    return results


@idasync
def declare_stack(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    items = arguments.get("items", arguments)
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        raise ValueError("items must be an object or list of objects")

    results = []
    for item in items:
        fn_ea = _parse_ea(item.get("addr"))
        var_name = str(item.get("name") or "").strip()
        type_name = str(item.get("ty") or item.get("type") or "").strip()
        offset = _parse_int_like(item.get("offset"), "offset")
        if not var_name or not type_name:
            raise ValueError("name and ty are required")
        try:
            func = idaapi.get_func(fn_ea)
            if func is None:
                raise ValueError(f"No function found at {_hex(fn_ea)}")
            tif = _resolve_type_info(type_name)
            ok = bool(ida_frame.define_stkvar(func, var_name, offset, tif))
            if ok:
                _refresh_decompiler(func.start_ea)
            results.append({"addr": _hex(func.start_ea), "name": var_name, "offset": hex(offset), "type": type_name, "ok": ok})
        except Exception as exc:
            results.append({"addr": _hex(fn_ea), "name": var_name, "offset": hex(offset), "type": type_name, "ok": False, "error": str(exc)})
    return results


@idasync
def delete_stack(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    items = arguments.get("items", arguments)
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        raise ValueError("items must be an object or list of objects")

    results = []
    for item in items:
        fn_ea = _parse_ea(item.get("addr"))
        var_name = str(item.get("name") or "").strip()
        if not var_name:
            raise ValueError("name is required")
        try:
            func = idaapi.get_func(fn_ea)
            if func is None:
                raise ValueError(f"No function found at {_hex(fn_ea)}")
            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                raise ValueError("No frame returned")
            idx, udm = frame_tif.get_udm(var_name)
            if not udm:
                raise ValueError(f"{var_name} not found")
            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                raise ValueError(f"{var_name} is a special frame member")
            offset = udm.offset // 8
            size = udm.size // 8
            if ida_frame.is_funcarg_off(func, offset):
                raise ValueError(f"{var_name} is an argument member")
            ok = bool(ida_frame.delete_frame_members(func, offset, offset + size))
            if ok:
                _refresh_decompiler(func.start_ea)
            results.append({"addr": _hex(func.start_ea), "name": var_name, "offset": hex(offset), "size": size, "ok": ok})
        except Exception as exc:
            results.append({"addr": _hex(fn_ea), "name": var_name, "ok": False, "error": str(exc)})
    return results


@idasync
def declare_type(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    decls_raw = arguments.get("decls", arguments.get("decl", arguments.get("type", "")))
    decls = _split_string_list(decls_raw)
    if not decls and isinstance(decls_raw, str) and decls_raw.strip():
        decls = [decls_raw.strip()]
    if not decls:
        raise ValueError("decl/decls is required")

    results = []
    for decl in decls:
        try:
            errors = ida_typeinf.parse_decls(None, decl, False, ida_typeinf.HTI_PAKDEF)
            ok = int(errors) == 0
            results.append({"decl": decl, "ok": ok, "errors": int(errors), "error": None if ok else "Failed to parse declaration"})
        except Exception as exc:
            results.append({"decl": decl, "ok": False, "errors": None, "error": str(exc)})
    return results


@idasync
def define_func(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    items = _ensure_list_of_dicts(arguments.get("items", arguments), "items")
    results = []
    for item in items:
        addr = _parse_ea(item.get("addr"))
        end_raw = item.get("end")
        end_ea = _parse_ea(end_raw) if str(end_raw or "").strip() else ida_idaapi.BADADDR
        try:
            existing = idaapi.get_func(addr)
            if existing is not None and existing.start_ea == addr:
                results.append({"addr": _hex(addr), "start": _hex(existing.start_ea), "end": _hex(existing.end_ea), "ok": False, "error": "Function already exists"})
                continue
            ok = bool(ida_funcs.add_func(addr, end_ea))
            func = idaapi.get_func(addr)
            results.append(
                {
                    "addr": _hex(addr),
                    "start": _hex(func.start_ea) if func else _hex(addr),
                    "end": _hex(func.end_ea) if func else (_hex(end_ea) if end_ea != ida_idaapi.BADADDR else ""),
                    "ok": ok,
                    "error": None if ok else "define_func failed",
                }
            )
        except Exception as exc:
            results.append({"addr": _hex(addr), "ok": False, "error": str(exc)})
    return results


@idasync
def define_code(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    items = _ensure_list_of_dicts(arguments.get("items", arguments), "items")
    results = []
    for item in items:
        ea = _parse_ea(item.get("addr"))
        try:
            length = int(ida_ua.create_insn(ea))
            ok = length > 0
            results.append({"addr": _hex(ea), "length": length, "ok": ok, "error": None if ok else "Failed to create instruction"})
        except Exception as exc:
            results.append({"addr": _hex(ea), "ok": False, "error": str(exc)})
    return results


@idasync
def undefine(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    items = _ensure_list_of_dicts(arguments.get("items", arguments), "items")
    results = []
    for item in items:
        start_ea = _parse_ea(item.get("addr"))
        end_raw = item.get("end")
        size_raw = item.get("size", 0)
        try:
            if str(end_raw or "").strip():
                end_ea = _parse_ea(end_raw)
                nbytes = max(0, end_ea - start_ea)
            elif size_raw:
                nbytes = max(0, int(size_raw))
            else:
                item_size = ida_bytes.get_item_size(start_ea)
                nbytes = max(1, int(item_size or 1))
            ok = bool(ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, nbytes))
            results.append({"addr": _hex(start_ea), "size": nbytes, "ok": ok, "error": None if ok else "undefine failed"})
        except Exception as exc:
            results.append({"addr": _hex(start_ea), "ok": False, "error": str(exc)})
    return results


@idasync
def define(arguments: dict[str, Any] | None = None) -> Any:
    arguments = arguments or {}
    kind = str(arguments.get("kind") or "").strip().lower()
    if not kind:
        raise ValueError("kind is required")
    if kind in {"function", "func"}:
        return define_func(arguments)
    if kind == "code":
        return define_code(arguments)
    if kind in {"undefine", "undef"}:
        return undefine(arguments)
    if kind == "type":
        if arguments.get("decls") or (arguments.get("decl") and not arguments.get("addr") and not arguments.get("symbol")):
            return declare_type(arguments)
        if arguments.get("decl") or arguments.get("signature"):
            return apply_decl(arguments)
        return set_type({"edits": arguments.get("edits", [arguments])})
    if kind == "struct":
        if arguments.get("fields"):
            return create_struct(arguments)
        return apply_struct(arguments)
    if kind == "array":
        return make_array(arguments)
    if kind == "stack":
        action = str(arguments.get("action") or "declare").strip().lower()
        if action in {"delete", "remove"}:
            return delete_stack(arguments)
        return declare_stack(arguments)
    raise ValueError(f"Unsupported define kind: {kind}")


@idasync
def get_data_item(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    flags = ida_bytes.get_flags(ea)
    func = idaapi.get_func(ea)
    kind = "unknown"
    if func is not None and ea == func.start_ea:
        kind = "function"
    elif ida_bytes.is_code(flags):
        kind = "code"
    elif ida_bytes.is_strlit(flags):
        kind = "string"
    elif ida_bytes.is_data(flags):
        kind = "data"
    size = ida_bytes.get_item_size(ea)
    preview_size = size if 0 < size <= 32 else 16
    raw = _read_bytes_raw(ea, max(0, preview_size)) if preview_size else b""
    line = ida_lines.generate_disasm_line(ea, 0)
    string_value = ""
    if kind == "string":
        try:
            stype = idc.get_str_type(ea)
            content = idc.get_strlit_contents(ea, -1, stype)
            if isinstance(content, bytes):
                string_value = content.decode("utf-8", "replace")
            elif isinstance(content, str):
                string_value = content
        except Exception:
            string_value = ""
    return {
        "address": _hex(ea),
        "segment": _segment_name(ea),
        "kind": kind,
        "name": _name_at(ea),
        "size": size,
        "type": _type_at(ea),
        "bytes": raw.hex(),
        "string": string_value,
        "disasm_preview": ida_lines.tag_remove(line or ""),
        "xrefs_to_count": sum(1 for _ in idautils.XrefsTo(ea, ida_xref.XREF_ALL)),
        "xrefs_from_count": sum(1 for _ in idautils.XrefsFrom(ea, ida_xref.XREF_ALL)),
    }


@idasync
def rename(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    batch = arguments.get("batch", arguments)
    if isinstance(batch, dict) and "addr" in batch and "name" in batch:
        batch = {"func": [batch]}
    results = {"func": [], "data": [], "local": [], "stack": []}
    for item in batch.get("func", []) or []:
        ea = _parse_ea(item.get("addr"))
        name = str(item.get("name") or "")
        ok = idaapi.set_name(ea, name, ida_name.SN_CHECK)
        if ok:
            _refresh_decompiler(ea)
        results["func"].append({"addr": _hex(ea), "name": name, "ok": bool(ok)})
    for item in batch.get("data", []) or []:
        ea = _parse_ea(item.get("addr") or item.get("old"))
        new_name = str(item.get("new") or item.get("name") or "")
        ok = idaapi.set_name(ea, new_name, ida_name.SN_CHECK)
        results["data"].append({"addr": _hex(ea), "name": new_name, "ok": bool(ok)})
    for item in batch.get("local", []) or []:
        results["local"].append({"item": item, "ok": False, "error": "local rename not implemented yet"})
    for item in batch.get("stack", []) or []:
        results["stack"].append({"item": item, "ok": False, "error": "stack rename not implemented yet"})
    return results


@idasync
def set_comments(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    items = arguments.get("items", arguments)
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        raise ValueError("items must be a dict or list of dicts")
    results = []
    for item in items:
        ea = _parse_ea(item.get("addr"))
        comment = str(item.get("comment") or item.get("text") or "")
        repeatable = bool(item.get("repeatable", False))
        ok = idaapi.set_cmt(ea, comment, repeatable)
        func = idaapi.get_func(ea)
        if func is not None and func.start_ea == ea:
            idc.set_func_cmt(ea, comment, 1 if repeatable else 0)
        if ok:
            _refresh_decompiler(ea)
        results.append({"addr": _hex(ea), "ok": bool(ok), "repeatable": repeatable})
    return results


@idasync
def set_type(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    edits = arguments.get("edits", arguments)
    if isinstance(edits, dict):
        edits = [edits]
    if not isinstance(edits, list):
        raise ValueError("edits must be a dict or list of dicts")
    results = []
    for edit in edits:
        kind = str(edit.get("kind") or "").lower()
        ea = _parse_ea(edit.get("addr"))
        alias_type = str(edit.get("type") or "").strip()
        decl = str(edit.get("signature") or edit.get("decl") or "").strip()
        ty = str(edit.get("ty") or "").strip()
        if alias_type and not decl and not ty:
            if "(" in alias_type and ")" in alias_type:
                decl = alias_type
                if not kind:
                    kind = "function"
            else:
                ty = alias_type
        ok = False
        if kind == "function" or decl:
            signature = decl or ty
            if not signature:
                raise ValueError("function type requires signature or ty")
            ok = ida_typeinf.apply_cdecl(None, ea, signature, ida_typeinf.TINFO_DEFINITE | ida_typeinf.TINFO_DELAYFUNC)
        else:
            if not ty:
                raise ValueError("set_type requires ty")
            ok = ida_typeinf.apply_cdecl(None, ea, f"{ty} value;", ida_typeinf.TINFO_DEFINITE)
        if ok:
            _refresh_decompiler(ea)
        results.append({"addr": _hex(ea), "kind": kind or "auto", "ok": bool(ok), "type": decl or ty})
    return results


@idasync
def apply_decl(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea, resolved_name = _resolve_decl_target(arguments)
    decl = str(arguments.get("decl") or arguments.get("type") or arguments.get("signature") or "").strip()
    if not decl:
        raise ValueError("decl is required")
    ok = bool(idc.SetType(ea, decl))
    if ok:
        _refresh_decompiler(ea)
    return {
        "addr": _hex(ea),
        "name": resolved_name,
        "decl": decl,
        "ok": ok,
        "applied_type": _type_at(ea),
    }


@idasync
def reanalyze_function(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    func = idaapi.get_func(ea)
    created = False
    if func is None:
        created = bool(ida_funcs.add_func(ea))
        func = idaapi.get_func(ea)
    if func is None:
        return {
            "ok": False,
            "addr": _hex(ea),
            "created": created,
            "error": f"No function found at {_hex(ea)}",
        }
    ida_auto.plan_range(func.start_ea, func.end_ea)
    ida_auto.auto_wait()
    _refresh_decompiler(func.start_ea)
    payload = _enclosing_function_payload(func.start_ea)
    payload.update({"ok": True, "created": created})
    return payload


@idasync
def create_struct(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    name = str(arguments.get("name") or "").strip()
    fields = arguments.get("fields", [])
    if not name:
        raise ValueError("name is required")
    if not isinstance(fields, list) or not fields:
        raise ValueError("fields must be a non-empty list")
    field_lines = []
    for field in fields:
        field_type = str(field.get("type") or "").strip()
        field_name = str(field.get("name") or "").strip()
        if not field_type or not field_name:
            raise ValueError(f"Invalid struct field: {field}")
        field_lines.append(f"    {field_type} {field_name};")
    decl = "typedef struct {name} {{\n{fields}\n}} {name};".format(name=name, fields="\n".join(field_lines))
    if hasattr(ida_typeinf, "del_named_type"):
        try:
            ida_typeinf.del_named_type(None, name, 0)
        except Exception:
            pass
    errors = ida_typeinf.parse_decls(None, decl, False, ida_typeinf.HTI_PAKDEF)
    ok = errors == 0 and _type_exists(name)
    return {"name": name, "ok": ok, "errors": int(errors), "decl": decl}


@idasync
def apply_struct(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    struct_name = str(arguments.get("struct_name") or arguments.get("name") or "").strip()
    if not struct_name:
        raise ValueError("struct_name is required")
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struct_name):
        raise ValueError(f"Unknown struct type: {struct_name}")
    applied = bool(ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE))
    created = bool(idc.create_struct(ea, -1, struct_name))
    if applied or created:
        _refresh_decompiler(ea)
    return {"addr": _hex(ea), "struct_name": struct_name, "ok": bool(applied or created), "apply_named_type": applied, "create_struct": created}


@idasync
def make_array(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    elem_type = str(arguments.get("elem_type") or "byte").strip()
    count = max(1, int(arguments.get("count", 1)))
    prepared = False
    if _primitive_create(ea, elem_type):
        prepared = True
    elif _type_exists(elem_type):
        tif = ida_typeinf.tinfo_t()
        tif.get_named_type(None, elem_type)
        prepared = bool(idc.create_struct(ea, -1, elem_type) or ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE))
    else:
        prepared = bool(ida_typeinf.apply_cdecl(None, ea, f"{elem_type} value;", ida_typeinf.TINFO_DEFINITE))
    if not prepared:
        raise RuntimeError(f"Unable to prepare array item at {_hex(ea)} for type {elem_type}")
    ok = bool(idc.make_array(ea, count))
    if ok:
        try:
            ida_typeinf.apply_cdecl(None, ea, f"{elem_type} value[{count}];", ida_typeinf.TINFO_DEFINITE)
        except Exception:
            pass
        _refresh_decompiler(ea)
    return {"addr": _hex(ea), "elem_type": elem_type, "count": count, "ok": ok}


@idasync
def save_database(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    path = str((arguments or {}).get("path") or "")
    ok = bool(idc.save_database(path, 0))
    return {"ok": ok, "path": path or idc.get_idb_path() or ""}


TOOL_DEFINITIONS = [
    {"name": "get_metadata", "description": "Return basic database metadata."},
    {"name": "inspect", "description": "High-level address inspection with optional decompile/disasm payloads."},
    {"name": "analysis_status", "description": "Return current autoanalysis status and function count."},
    {"name": "wait_for_autoanalysis", "description": "Block until autoanalysis is complete or timeout expires."},
    {"name": "list_segments", "description": "List segments and ranges."},
    {"name": "list_globals", "description": "List named globals with pagination."},
    {"name": "imports", "description": "List imports with pagination."},
    {"name": "list_functions", "description": "List functions with pagination."},
    {"name": "lookup_funcs", "description": "Lookup functions by address or name."},
    {"name": "get_function", "description": "Return function metadata for an address."},
    {"name": "get_enclosing_function", "description": "Return the function containing the queried address."},
    {"name": "decompile", "description": "Decompile a function with Hex-Rays."},
    {"name": "get_decompile_line_map", "description": "Return pseudocode lines with best-effort disassembly address mapping."},
    {"name": "disasm_function", "description": "Disassemble the full containing function for an address."},
    {"name": "disasm", "description": "Disassemble a function or address range."},
    {"name": "get_xrefs_to", "description": "Return cross-references to an address."},
    {"name": "get_xrefs_from", "description": "Return cross-references from an address."},
    {"name": "xrefs_to", "description": "Compatibility alias for xref lookup on one or more addresses."},
    {"name": "callees", "description": "Return direct callees for one or more functions."},
    {"name": "basic_blocks", "description": "Return CFG basic blocks for one or more functions."},
    {"name": "xrefs_to_field", "description": "Return cross-references to a named struct field."},
    {"name": "list_strings", "description": "List strings in the database."},
    {"name": "find_bytes", "description": "Search byte patterns with wildcard support."},
    {"name": "find_text", "description": "Search strings, names, comments, or disassembly text."},
    {"name": "find_regex", "description": "Search string literals with a case-insensitive regex."},
    {"name": "find_immediates", "description": "Search executable instructions for immediate operand values."},
    {"name": "find_insns", "description": "Search for instruction text sequences."},
    {"name": "search", "description": "High-level search API for text/regex/bytes/immediates/instructions."},
    {"name": "inspect_addr", "description": "Inspect an address and return code/data/function context."},
    {"name": "get_data_item", "description": "Inspect what exists at a specific address."},
    {"name": "get_bytes", "description": "Compatibility memory-read helper returning spaced hex bytes."},
    {"name": "get_int", "description": "Compatibility integer-read helper using i8/u32/i16be style types."},
    {"name": "get_string", "description": "Compatibility string-read helper for one or more addresses."},
    {"name": "get_global_value", "description": "Read named globals or addresses with simple typed rendering."},
    {"name": "read", "description": "High-level read API for bytes/int/string/struct/array/global."},
    {"name": "read_bytes", "description": "Read raw bytes."},
    {"name": "read_byte", "description": "Read one byte."},
    {"name": "read_word", "description": "Read one word."},
    {"name": "read_dword", "description": "Read one dword."},
    {"name": "read_qword", "description": "Read one qword."},
    {"name": "read_array", "description": "Read an array as typed values or raw items."},
    {"name": "hex_dump", "description": "Render a hex dump."},
    {"name": "read_struct", "description": "Read a struct instance at an address."},
    {"name": "xrefs", "description": "High-level xref API for to/from or struct-field lookups."},
    {"name": "stack_frame", "description": "Return stack-frame variables for one or more functions."},
    {"name": "declare_type", "description": "Register one or more C declarations in IDA's type system."},
    {"name": "define", "description": "High-level define API for function/code/type/struct/array/stack/undefine."},
    {"name": "define_func", "description": "Define functions at one or more addresses."},
    {"name": "define_code", "description": "Define code instructions at one or more addresses."},
    {"name": "undefine", "description": "Undefine items back to raw bytes."},
    {"name": "declare_stack", "description": "Create stack variables in a function frame."},
    {"name": "delete_stack", "description": "Delete stack variables from a function frame."},
    {"name": "rename", "description": "Rename functions or data symbols."},
    {"name": "set_comments", "description": "Set comments at addresses."},
    {"name": "set_type", "description": "Apply C declarations or types to addresses."},
    {"name": "apply_decl", "description": "Apply a C declaration to a symbol/address like the GUI Y command."},
    {"name": "reanalyze_function", "description": "Create/reanalyze the function containing an address."},
    {"name": "create_struct", "description": "Create a named struct type from field definitions."},
    {"name": "apply_struct", "description": "Apply a named struct type at an address."},
    {"name": "make_array", "description": "Convert the current item into an array."},
    {"name": "save_database", "description": "Save the current database."},
]


TOOL_HANDLERS: dict[str, Callable[[dict[str, Any] | None], Any]] = {
    "get_metadata": get_metadata,
    "inspect": inspect,
    "analysis_status": analysis_status,
    "wait_for_autoanalysis": wait_for_autoanalysis,
    "list_segments": list_segments,
    "list_globals": list_globals,
    "imports": imports,
    "list_functions": list_functions,
    "lookup_funcs": lookup_funcs,
    "get_function": get_function,
    "get_enclosing_function": get_enclosing_function,
    "decompile": decompile,
    "get_decompile_line_map": get_decompile_line_map,
    "disasm_function": disasm_function,
    "disasm": disasm,
    "get_xrefs_to": get_xrefs_to,
    "get_xrefs_from": get_xrefs_from,
    "xrefs_to": xrefs_to,
    "callees": callees,
    "basic_blocks": basic_blocks,
    "xrefs_to_field": xrefs_to_field,
    "list_strings": list_strings,
    "find_bytes": find_bytes,
    "find_text": find_text,
    "find_regex": find_regex,
    "find_immediates": find_immediates,
    "find_insns": find_insns,
    "search": search,
    "inspect_addr": inspect_addr,
    "get_data_item": get_data_item,
    "get_bytes": get_bytes,
    "get_int": get_int,
    "get_string": get_string,
    "get_global_value": get_global_value,
    "read": read,
    "read_bytes": read_bytes,
    "read_byte": read_byte,
    "read_word": read_word,
    "read_dword": read_dword,
    "read_qword": read_qword,
    "read_array": read_array,
    "hex_dump": hex_dump,
    "read_struct": read_struct,
    "xrefs": xrefs,
    "stack_frame": stack_frame,
    "declare_type": declare_type,
    "define": define,
    "define_func": define_func,
    "define_code": define_code,
    "undefine": undefine,
    "declare_stack": declare_stack,
    "delete_stack": delete_stack,
    "rename": rename,
    "set_comments": set_comments,
    "set_type": set_type,
    "apply_decl": apply_decl,
    "reanalyze_function": reanalyze_function,
    "create_struct": create_struct,
    "apply_struct": apply_struct,
    "make_array": make_array,
    "save_database": save_database,
}


def call_tool(tool_name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    handler = TOOL_HANDLERS.get(tool_name)
    if handler is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return _tool_result(handler(arguments))
