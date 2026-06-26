from __future__ import annotations

from collections import defaultdict
import json
import os
from pathlib import Path
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
_WINDOWS_DRIVE_RE = re.compile(r"^(?P<drive>[a-zA-Z]):[\\/](?P<rest>.*)$")
_WSL_DRIVE_RE = re.compile(r"^/mnt/(?P<drive>[a-zA-Z])/(?P<rest>.*)$")


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


def _trim_summary_text(text: str, limit: int = 120) -> str:
    normalized = str(text or "").strip().replace("\n", " ")
    if not normalized:
        return "result"
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(1, limit - 3)] + "..."


def _summary_text(payload: Any) -> str:
    if isinstance(payload, dict):
        mode = str(payload.get("mode") or "").strip()
        addr = str(payload.get("addr") or payload.get("address") or "").strip()
        name = str(
            payload.get("name")
            or payload.get("display_name")
            or payload.get("struct_name")
            or payload.get("function")
            or payload.get("imported_name")
            or ""
        ).strip()
        if mode == "decompile":
            target = name or addr or "<unknown>"
            return _trim_summary_text(f"decompile {target}")
        if mode == "disasm":
            target = name or addr or "<unknown>"
            return _trim_summary_text(f"disasm {target}")
        if "items" in payload and isinstance(payload.get("items"), list):
            label = name or mode or "result"
            return _trim_summary_text(f"{label} items={len(payload.get('items') or [])}")
        if "matches" in payload and isinstance(payload.get("matches"), list):
            return _trim_summary_text(f"matches={len(payload.get('matches') or [])}")
        if "members" in payload and isinstance(payload.get("members"), list):
            target = name or str(payload.get("struct_name") or addr or "struct")
            return _trim_summary_text(f"{target} members={len(payload.get('members') or [])}")
        if "code" in payload and isinstance(payload.get("code"), str):
            target = name or addr or mode or "result"
            return _trim_summary_text(f"{target} code")
        if "ok" in payload:
            parts = [f"ok={bool(payload.get('ok'))}"]
            if name:
                parts.append(f"name={name}")
            elif addr:
                parts.append(f"addr={addr}")
            elif mode:
                parts.append(f"mode={mode}")
            if payload.get("error"):
                parts.append(f"error={payload.get('error')}")
            return _trim_summary_text(" ".join(parts))
        keys = [key for key in payload.keys() if key not in {"content", "structuredContent", "meta"}]
        preview = ", ".join(keys[:4])
        return _trim_summary_text(f"result {{{preview}}}" if preview else "result")
    if isinstance(payload, list):
        return _trim_summary_text(f"results={len(payload)}")
    if isinstance(payload, str):
        return _trim_summary_text(payload)
    return _trim_summary_text(str(payload))


def _tool_result(payload: Any, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": _summary_text(payload)}],
        "structuredContent": payload,
        "meta": {"content_mode": "summary"},
        "isError": is_error,
    }


def _bool_argument(arguments: dict[str, Any] | None, key: str, default: bool = False) -> bool:
    if not isinstance(arguments, dict) or key not in arguments:
        return default
    value = arguments.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off"}
    if value is None:
        return False
    return bool(value)


def _detail_value(arguments: dict[str, Any] | None, default: str = "slim") -> str:
    if not isinstance(arguments, dict):
        return default
    detail = str(arguments.get("detail") or "").strip().lower()
    if detail in {"", "default"}:
        return default
    if detail in {"full", "verbose"}:
        return "full"
    if detail in {"slim", "compact", "summary"}:
        return "slim"
    return default


def _detail_is_full(arguments: dict[str, Any] | None, default: str = "slim") -> bool:
    return _bool_argument(arguments, "full", False) or _detail_value(arguments, default=default) == "full"


def _pick_fields(entry: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    return {field: entry[field] for field in fields if field in entry}


_AUTO_PAD_RE = re.compile(r"^__pad_[0-9A-Fa-f]+(?:_[0-9A-Fa-f]+)?$")


def _normalize_export_path(path: str) -> Path:
    raw = str(path or "").strip()
    if not raw:
        raise ValueError("path is required")
    match = _WSL_DRIVE_RE.match(raw)
    if match:
        if os.name != "nt":
            return Path(raw).expanduser()
        rest = match.group("rest").replace("/", "\\")
        return Path(f"{match.group('drive').upper()}:\\{rest}")
    match = _WINDOWS_DRIVE_RE.match(raw)
    if match:
        if os.name != "nt":
            rest = match.group("rest").replace("\\", "/")
            return Path(f"/mnt/{match.group('drive').lower()}/{rest}").expanduser()
        rest = match.group("rest").replace("/", "\\")
        return Path(f"{match.group('drive').upper()}:\\{rest}")
    return Path(raw).expanduser()


def _c_comment_text(value: Any) -> str:
    return str(value or "").replace("*/", "* /")


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
        ida_hexrays.mark_cfunc_dirty(func.start_ea, False)
    except Exception:
        pass
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            try:
                cfunc.recalc_item_addresses()
            except Exception:
                pass
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


def _coerce_decl_list(value: Any) -> list[str]:
    decls = _split_string_list(value)
    if not decls and isinstance(value, str) and value.strip():
        decls = [value.strip()]
    return [item.strip() for item in decls if str(item).strip()]


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


def _member_declaration(field_type: str, field_name: str) -> str:
    normalized = str(field_type or "").strip().rstrip(";")
    if not normalized:
        raise ValueError("Missing field type")
    if "{name}" in normalized:
        return normalized.format(name=field_name)
    bracket_index = normalized.find("[")
    if bracket_index > 0:
        return f"{normalized[:bracket_index].rstrip()} {field_name}{normalized[bracket_index:]}"
    return f"{normalized} {field_name}"


def _parse_member_tinfo(field_type: str, field_name: str) -> ida_typeinf.tinfo_t:
    tif = ida_typeinf.tinfo_t()
    declaration = _member_declaration(field_type, field_name)
    if tif.parse(f"{declaration};"):
        return tif
    return _resolve_type_info(field_type)


def _type_size_bytes(field_type: str, field_name: str = "__field") -> int:
    tif = _parse_member_tinfo(field_type, field_name)
    size = int(tif.get_size())
    if size <= 0:
        raise ValueError(f"Unable to determine size for type: {field_type}")
    return size


def _parse_offset_bytes(item: dict[str, Any]) -> int:
    if "bit_offset" in item:
        bit_offset = _parse_int_like(item.get("bit_offset"), "bit_offset")
        if bit_offset % 8 != 0:
            raise ValueError(f"bit_offset must be byte-aligned: {bit_offset}")
        return bit_offset // 8
    for key in ("offset", "byte_offset"):
        if key in item:
            return _parse_int_like(item.get(key), key)
    raise ValueError(f"Missing offset/byte_offset in field: {item}")


def _normalize_struct_field(item: dict[str, Any], index: int = 0) -> dict[str, Any]:
    name = str(item.get("name") or "").strip()
    field_type = str(item.get("type") or item.get("ty") or "").strip()
    if not name or not field_type:
        raise ValueError(f"Invalid struct field: {item}")
    offset = _parse_offset_bytes(item)
    size = int(item.get("size") or item.get("byte_size") or 0)
    if size <= 0:
        size = _type_size_bytes(field_type, name)
    return {
        "name": name,
        "type": field_type,
        "offset": offset,
        "size": size,
        "comment": str(item.get("comment") or item.get("cmt") or "").strip(),
        "index": index,
    }


def _build_padded_layout(fields: list[dict[str, Any]], total_size: int | None = None) -> list[dict[str, Any]]:
    logical_fields = sorted((_normalize_struct_field(item, idx) for idx, item in enumerate(fields)), key=lambda x: (x["offset"], x["index"]))
    layout: list[dict[str, Any]] = []
    cursor = 0
    for field in logical_fields:
        offset = field["offset"]
        size = field["size"]
        if offset < cursor:
            raise ValueError(f"Overlapping field at 0x{offset:X}: {field['name']}")
        if offset > cursor:
            gap = offset - cursor
            layout.append(
                {
                    "name": f"__pad_{cursor:04X}",
                    "type": "unsigned char" if gap == 1 else f"unsigned char[{gap}]",
                    "offset": cursor,
                    "size": gap,
                    "auto_pad": True,
                    "comment": "",
                }
            )
            cursor = offset
        layout.append({**field, "auto_pad": False})
        cursor = offset + size
    if total_size is not None and total_size > cursor:
        gap = total_size - cursor
        layout.append(
            {
                "name": f"__pad_{cursor:04X}",
                "type": "unsigned char" if gap == 1 else f"unsigned char[{gap}]",
                "offset": cursor,
                "size": gap,
                "auto_pad": True,
                "comment": "",
            }
        )
    return layout


def _struct_fields_from_tif(tif: ida_typeinf.tinfo_t, *, include_auto_pad: bool = True) -> list[dict[str, Any]]:
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        raise ValueError("Unable to enumerate structure members")
    fields: list[dict[str, Any]] = []
    for idx, udm in enumerate(udt):
        if udm.is_gap():
            continue
        name = str(udm.name or "")
        field = {
            "name": name,
            "type": str(udm.type),
            "offset": udm.offset // 8,
            "size": max(0, udm.size // 8),
            "comment": "",
            "auto_pad": bool(_AUTO_PAD_RE.match(name)),
            "index": idx,
        }
        if include_auto_pad or not field["auto_pad"]:
            fields.append(field)
    return fields


def _get_named_struct_tinfo(struct_name: str) -> ida_typeinf.tinfo_t:
    tif = _resolve_type_info(struct_name)
    if not tif.is_udt():
        raise ValueError(f"{struct_name} is not a struct/union type")
    return tif


def _save_named_struct(struct_name: str, layout: list[dict[str, Any]]) -> dict[str, Any]:
    tif = ida_typeinf.tinfo_t()
    tif.create_udt()
    for field in layout:
        tif.add_udm(field["name"], _parse_member_tinfo(field["type"], field["name"]), field["offset"] * 8)
    flags = ida_typeinf.NTF_TYPE | ida_typeinf.NTF_COPY
    if _type_exists(struct_name):
        flags |= ida_typeinf.NTF_REPLACE
    code = tif.set_named_type(None, struct_name, flags)
    ok = int(code) == int(ida_typeinf.TERR_OK) and _type_exists(struct_name)
    return {"ok": ok, "code": int(code)}


def _header_decl_from_layout(struct_name: str, layout: list[dict[str, Any]], total_size: int) -> str:
    lines = [f"typedef struct {struct_name} {{"]
    for field in layout:
        decl = _member_declaration(field["type"], field["name"])
        lines.append(f"    /* 0x{field['offset']:X} */ {decl};")
    lines.append(f"}} {struct_name}; /* size: 0x{total_size:X} */")
    return "\n".join(lines)


def _parse_exported_struct_text(text: str) -> dict[str, Any]:
    struct_match = re.search(r"typedef\s+struct\s+(\w+)\s*\{(?P<body>.*?)\}\s*(\w+)\s*;\s*/\*\s*size:\s*0x([0-9A-Fa-f]+)\s*\*/", text, re.S)
    if not struct_match:
        raise ValueError("Unsupported struct header format")
    name = struct_match.group(1)
    body = struct_match.group("body")
    size = int(struct_match.group(4), 16)
    fields: list[dict[str, Any]] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"/\*\s*0x([0-9A-Fa-f]+)\s*\*/\s*(.+?)\s*;", line)
        if not match:
            continue
        offset = int(match.group(1), 16)
        decl = match.group(2).strip()
        name_match = re.search(r"([A-Za-z_]\w*)(\s*(\[[^\]]+\])*)$", decl)
        if not name_match:
            raise ValueError(f"Unable to parse field declaration: {decl}")
        field_name = name_match.group(1)
        field_type = decl[: name_match.start(1)].rstrip() + (name_match.group(2) or "")
        fields.append({"name": field_name, "type": field_type.strip(), "offset": offset})
    return {"name": name, "size": size, "fields": fields}


def _load_struct_reference(arguments: dict[str, Any]) -> dict[str, Any]:
    if arguments.get("decl"):
        return _parse_exported_struct_text(str(arguments.get("decl") or ""))
    path = str(arguments.get("path") or "").strip()
    if not path:
        raise ValueError("path or decl is required")
    target = Path(path).expanduser()
    text = target.read_text(encoding="utf-8", errors="ignore")
    if target.suffix.lower() == ".json":
        payload = json.loads(text)
        if "fields" not in payload:
            raise ValueError("Invalid struct json payload")
        return payload
    return _parse_exported_struct_text(text)


def _classify_xref_access(ea: int) -> dict[str, Any]:
    insn = _decode_insn_at(ea)
    if insn is None:
        return {
            "access_hint": "unknown",
            "confidence": "none",
            "basis": "instruction_decode_failed",
        }
    mem_operand_types = {ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ}
    ops = [insn.ops[idx] for idx in range(ida_ua.UA_MAXOP) if insn.ops[idx].type != ida_ua.o_void]
    if not ops:
        return {
            "access_hint": "unknown",
            "confidence": "none",
            "basis": "no_operands",
        }
    if len(ops) == 1 and ops[0].type in mem_operand_types:
        return {
            "access_hint": "read_write",
            "confidence": "low",
            "basis": "single_memory_operand",
        }
    if ops[0].type in mem_operand_types:
        return {
            "access_hint": "write_like",
            "confidence": "medium",
            "basis": "memory_operand_is_destination",
        }
    if any(op.type in mem_operand_types for op in ops[1:]):
        return {
            "access_hint": "read_like",
            "confidence": "medium",
            "basis": "memory_operand_is_source",
        }
    return {
        "access_hint": "unknown",
        "confidence": "low",
        "basis": "no_memory_operand_match",
    }


def _find_cfunc_lvar(func_ea: int, name: str):
    _func, cfunc = _decompile_cfunc(func_ea)
    for lvar in cfunc.lvars:
        if str(getattr(lvar, "name", "") or "") == name:
            return cfunc, lvar
    raise ValueError(f"Local variable not found: {name}")


def _apply_struct_to_local(func_ea: int, local_name: str, struct_name: str) -> dict[str, Any]:
    tif = _get_named_struct_tinfo(struct_name)
    cfunc, lvar = _find_cfunc_lvar(func_ea, local_name)
    info = ida_hexrays.lvar_saved_info_t()
    info.ll = lvar
    info.type = tif
    info.size = int(tif.get_size())
    ok = bool(ida_hexrays.modify_user_lvar_info(cfunc.entry_ea, ida_hexrays.MLI_TYPE, info))
    if ok:
        _refresh_decompiler(cfunc.entry_ea)
    return {"addr": _hex(cfunc.entry_ea), "name": local_name, "struct_name": struct_name, "ok": ok, "kind": "local"}


def _apply_struct_to_stack(func_ea: int, item: dict[str, Any], struct_name: str) -> dict[str, Any]:
    tif = _get_named_struct_tinfo(struct_name)
    target_name = str(item.get("name") or "").strip()
    if target_name:
        try:
            cfunc, lvar = _find_cfunc_lvar(func_ea, target_name)
            info = ida_hexrays.lvar_saved_info_t()
            info.ll = lvar
            info.type = tif
            info.size = int(tif.get_size())
            ok = bool(ida_hexrays.modify_user_lvar_info(cfunc.entry_ea, ida_hexrays.MLI_TYPE, info))
            if ok:
                _refresh_decompiler(cfunc.entry_ea)
                return {
                    "addr": _hex(cfunc.entry_ea),
                    "name": target_name,
                    "struct_name": struct_name,
                    "ok": True,
                    "kind": "stack",
                    "applied_via": "lvar_saved_info",
                }
        except Exception:
            pass

    func = idaapi.get_func(func_ea)
    if func is None:
        raise ValueError(f"No function found at {_hex(func_ea)}")
    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        raise ValueError("No frame")
    udt = ida_typeinf.udt_type_data_t()
    frame_tif.get_udt_details(udt)
    target_offset = item.get("offset")
    selected = None
    for udm in udt:
        if udm.is_gap():
            continue
        off = udm.offset // 8
        if target_name and str(udm.name or "") == target_name:
            selected = (str(udm.name or ""), off)
            break
        if target_offset is not None and off == _parse_int_like(target_offset, "offset"):
            selected = (str(udm.name or ""), off)
            break
    if selected is None:
        raise ValueError("Stack variable not found")
    var_name, soff = selected
    fp_offset = ida_frame.soff_to_fpoff(func, soff)
    ok = bool(ida_frame.define_stkvar(func, var_name, fp_offset, tif))
    if ok:
        _refresh_decompiler(func.start_ea)
    return {
        "addr": _hex(func.start_ea),
        "name": var_name,
        "offset": _hex(soff),
        "struct_name": struct_name,
        "ok": ok,
        "kind": "stack",
        "applied_via": "define_stkvar",
    }


def _workflow_entries_ok(group: list[Any]) -> bool:
    for entry in group:
        if not isinstance(entry, dict):
            continue
        if entry.get("ok") is False:
            return False
        nested = entry.get("items")
        if isinstance(nested, list) and not _workflow_entries_ok(nested):
            return False
    return True


def _workflow_entries_changed(group: list[Any]) -> int:
    count = 0
    for entry in group:
        if not isinstance(entry, dict):
            continue
        if entry.get("ok") is True:
            count += 1
        elif "ok_count" in entry and int(entry.get("ok_count") or 0) > 0:
            count += int(entry.get("ok_count") or 0)
        nested = entry.get("items")
        if isinstance(nested, list):
            count += _workflow_entries_changed(nested)
    return count


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
    full = _detail_is_full(arguments)
    include_decompile = bool(arguments.get("include_decompile", False)) or full
    include_disasm = bool(arguments.get("include_disasm", False)) or full
    include_line_map = bool(arguments.get("include_line_map", False)) or full
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
    full = _detail_is_full(arguments)
    func = idaapi.get_func(ea)
    fallback = str(arguments.get("fallback") or "disasm").strip().lower()
    if func is None:
        if fallback not in {"disasm", "asm"}:
            raise ValueError(f"No function found at {_hex(ea)}")
        payload = {
            "addr": _hex(ea),
            "name": "",
            "mode": "disasm",
            "decompile_error": f"No function found at {_hex(ea)}",
            "instructions": _disasm_window(ea, min(max(1, int(arguments.get('max_instructions', 200))), 2000)),
        }
        if full:
            payload["line_map"] = {"items": [], "count": 0, "error": payload["decompile_error"]}
        return payload
    start_ea = func.start_ea
    name = ida_funcs.get_func_name(start_ea) or ""
    try:
        _func, cfunc = _decompile_cfunc(start_ea)
        payload = {"addr": _hex(start_ea), "name": name, "mode": "decompile", "code": str(cfunc)}
        if full:
            try:
                payload["line_map"] = _decompile_line_map_payload(start_ea)
            except Exception as exc:
                payload["line_map_error"] = str(exc)
        return payload
    except Exception as exc:
        if fallback not in {"disasm", "asm"}:
            raise
        instructions = []
        for idx, item_ea in enumerate(idautils.FuncItems(start_ea)):
            if idx >= 4000:
                break
            line = ida_lines.generate_disasm_line(item_ea, 0)
            instructions.append({"address": _hex(item_ea), "text": ida_lines.tag_remove(line or "")})
        payload = {
            "addr": _hex(start_ea),
            "name": name,
            "mode": "disasm",
            "decompile_error": str(exc),
            "instructions": instructions,
        }
        if full:
            payload["line_map_error"] = str(exc)
        return payload


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
    full = _detail_is_full(arguments)
    offset = max(0, int(arguments.get("offset", 0)))
    count = max(0, int(arguments.get("count", 100)))
    filt = str(arguments.get("filter", "") or "").lower()
    strings = idautils.Strings()
    items = []
    for string in strings:
        value = str(string)
        if filt and filt not in value.lower():
            continue
        item = {
            "address": _hex(string.ea),
            "length": int(string.length),
            "type": int(string.strtype),
            "value": value,
        }
        items.append(item if full else _pick_fields(item, ["address", "value"]))
    total = len(items)
    if count == 0:
        sliced = items[offset:]
    else:
        sliced = items[offset : offset + count]
    return {"items": sliced, "offset": offset, "count": len(sliced), "total": total}


@idasync
def find_bytes(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    full = _detail_is_full(arguments)
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
                    item = {"address": _hex(ea), "segment": _segment_name(ea), "name": _name_at(ea)}
                    matches.append(item if full else _pick_fields(item, ["address"]))
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
    full = _detail_is_full(arguments)
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
    summary: dict[str, int] = {}

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
        summary[kind] = summary.get(kind, 0) + 1
        matches.append(entry if full else _pick_fields(entry, ["kind", "address", "text"]))

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
    return {
        "query": query,
        "kinds": sorted(normalized_kinds),
        "summary": summary,
        "items": sliced,
        "offset": offset,
        "count": len(sliced),
        "total": total,
        "truncated": offset + len(sliced) < total,
    }


@idasync
def find_regex(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    full = _detail_is_full(arguments)
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
        item = {
            "address": _hex(string.ea),
            "string": value,
            "segment": _segment_name(string.ea),
            "name": _name_at(string.ea),
            "length": int(string.length),
            "strtype": int(string.strtype),
        }
        matches.append(item if full else _pick_fields(item, ["address", "string"]))
    return {
        "pattern": pattern,
        "count": len(matches),
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


@idasync
def find_immediates(arguments: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    arguments = arguments or {}
    full = _detail_is_full(arguments)
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
                            item = {
                                "address": _hex(current),
                                "segment": _segment_name(current),
                                "text": line,
                                "function": ida_funcs.get_func_name(current) or "",
                            }
                            matches.append(item if full else _pick_fields(item, ["address", "text"]))
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
    full = _detail_is_full(arguments)
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
            item = {
                "address": _hex(head),
                "segment": _segment_name(head),
                "function": ida_funcs.get_func_name(head) or "",
                "lines": matched_lines,
            }
            matches.append(item if full else _pick_fields(item, ["address", "lines"]))
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
    full = _detail_is_full(arguments)
    ea = _parse_ea(arguments.get("addr"))
    elem_type = str(arguments.get("elem_type", "byte") or "byte").lower()
    count = max(0, int(arguments.get("count", 0)))
    items = []
    if elem_type in PRIMITIVE_READERS:
        elem_size, _fmt, unpacker = PRIMITIVE_READERS[elem_type]
        for idx in range(count):
            current = ea + idx * elem_size
            data = _read_bytes_raw(current, elem_size)
            entry = {"index": idx, "addr": _hex(current), "value": unpacker(data), "hex": data.hex()}
            items.append(entry if full else _pick_fields(entry, ["index", "addr", "value"]))
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
        entry = {"index": idx, "addr": _hex(current), "size": elem_size, "hex": data.hex()}
        items.append(entry if full else _pick_fields(entry, ["index", "addr", "size"]))
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
    full = _detail_is_full(arguments)
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
        members.append(item if full else _pick_fields(item, ["name", "offset", "address", "size", "type", "value"]))

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
    decls = _coerce_decl_list(decls_raw)
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
    if not isinstance(batch, dict):
        raise ValueError("batch must be an object")
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
        try:
            fn_ea = _parse_ea(item.get("func_addr") or item.get("addr"))
            old_name = str(item.get("old") or item.get("name") or "").strip()
            new_name = str(item.get("new") or "").strip()
            if not old_name or not new_name:
                raise ValueError("local rename requires func_addr/addr, old/name, and new")
            func = idaapi.get_func(fn_ea)
            if func is None:
                raise ValueError(f"No function found at {_hex(fn_ea)}")
            ok = bool(ida_hexrays.rename_lvar(func.start_ea, old_name, new_name))
            if ok:
                _refresh_decompiler(func.start_ea)
            results["local"].append({"addr": _hex(func.start_ea), "old": old_name, "new": new_name, "ok": ok, "error": None if ok else "Rename failed"})
        except Exception as exc:
            results["local"].append({"item": item, "ok": False, "error": str(exc)})
    for item in batch.get("stack", []) or []:
        try:
            fn_ea = _parse_ea(item.get("func_addr") or item.get("addr"))
            old_name = str(item.get("old") or item.get("name") or "").strip()
            new_name = str(item.get("new") or "").strip()
            if not old_name or not new_name:
                raise ValueError("stack rename requires func_addr/addr, old/name, and new")
            func = idaapi.get_func(fn_ea)
            if func is None:
                raise ValueError(f"No function found at {_hex(fn_ea)}")
            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                raise ValueError("No frame")
            idx, udm = frame_tif.get_udm(old_name)
            if not udm:
                raise ValueError(f"{old_name} not found")
            tid = frame_tif.get_udm_tid(idx)
            if ida_frame.is_special_frame_member(tid):
                raise ValueError("Special frame member")
            udm_current = ida_typeinf.udm_t()
            if not frame_tif.get_udm_by_tid(udm_current, tid):
                raise ValueError("Unable to resolve stack member")
            offset = udm_current.offset // 8
            if ida_frame.is_funcarg_off(func, offset):
                raise ValueError("Argument member")
            fp_offset = ida_frame.soff_to_fpoff(func, offset)
            ok = bool(ida_frame.define_stkvar(func, new_name, fp_offset, udm_current.type))
            if ok:
                _refresh_decompiler(func.start_ea)
            results["stack"].append({"addr": _hex(func.start_ea), "old": old_name, "new": new_name, "ok": ok, "error": None if ok else "Rename failed"})
        except Exception as exc:
            results["stack"].append({"item": item, "ok": False, "error": str(exc)})
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
    supporting_decls = _coerce_decl_list(
        arguments.get("supporting_decls", arguments.get("supporting_decl", arguments.get("decls", [])))
    )
    supporting_results: list[dict[str, Any]] = []
    if supporting_decls:
        supporting_results = declare_type({"decls": supporting_decls})
        if not all(bool(item.get("ok")) for item in supporting_results):
            return {
                "addr": _hex(ea),
                "name": resolved_name,
                "decl": decl,
                "ok": False,
                "error": "Failed to parse supporting declarations",
                "supporting_decls": supporting_results,
                "applied_type": _type_at(ea),
            }
    ok = bool(idc.SetType(ea, decl))
    if ok:
        _refresh_decompiler(ea)
    return {
        "addr": _hex(ea),
        "name": resolved_name,
        "decl": decl,
        "ok": ok,
        "supporting_decls": supporting_results,
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
    if _type_exists(name):
        return {"name": name, "ok": False, "errors": None, "decl": decl, "error": f"Type already exists: {name}"}
    errors = ida_typeinf.parse_decls(None, decl, False, ida_typeinf.HTI_PAKDEF)
    ok = errors == 0 and _type_exists(name)
    return {"name": name, "ok": ok, "errors": int(errors), "decl": decl, "error": None if ok else "Failed to parse declaration"}


@idasync
def create_padded_struct_from_map(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    name = str(arguments.get("name") or "").strip()
    fields = arguments.get("fields", [])
    total_size_arg = arguments.get("size")
    if not name:
        raise ValueError("name is required")
    if not isinstance(fields, list) or not fields:
        raise ValueError("fields must be a non-empty list")
    total_size = _parse_int_like(total_size_arg, "size") if total_size_arg not in (None, "") else None
    layout = _build_padded_layout(fields, total_size=total_size)
    materialized = _save_named_struct(name, layout)
    logical_count = len([field for field in layout if not field.get("auto_pad")])
    total_size_value = max((field["offset"] + field["size"] for field in layout), default=0)
    return {
        "name": name,
        "ok": materialized["ok"],
        "code": materialized["code"],
        "field_count": logical_count,
        "layout_count": len(layout),
        "size": total_size_value,
        "decl": _header_decl_from_layout(name, layout, total_size_value),
    }


@idasync
def upsert_struct(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    name = str(arguments.get("name") or "").strip()
    incoming = arguments.get("fields", [])
    total_size_arg = arguments.get("size")
    if not name:
        raise ValueError("name is required")
    if not isinstance(incoming, list) or not incoming:
        raise ValueError("fields must be a non-empty list")

    existing_fields: list[dict[str, Any]] = []
    existed = _type_exists(name)
    if existed:
        tif = _get_named_struct_tinfo(name)
        existing_fields = _struct_fields_from_tif(tif, include_auto_pad=False)

    merged_by_key: dict[tuple[int, str], dict[str, Any]] = {}
    for field in existing_fields:
        merged_by_key[(field["offset"], field["name"])] = {
            "name": field["name"],
            "type": field["type"],
            "offset": field["offset"],
            "size": field["size"],
            "comment": field.get("comment", ""),
        }
    for idx, raw in enumerate(incoming):
        field = _normalize_struct_field(raw, idx)
        replaced = False
        for key in list(merged_by_key.keys()):
            current = merged_by_key[key]
            if current["offset"] == field["offset"] or current["name"] == field["name"]:
                merged_by_key.pop(key, None)
                replaced = True
        merged_by_key[(field["offset"], field["name"])] = field

    merged_fields = sorted(merged_by_key.values(), key=lambda x: (x["offset"], x["name"]))
    inferred_size = max((field["offset"] + field["size"] for field in merged_fields), default=0)
    total_size = _parse_int_like(total_size_arg, "size") if total_size_arg not in (None, "") else inferred_size
    layout = _build_padded_layout(merged_fields, total_size=total_size)
    materialized = _save_named_struct(name, layout)
    return {
        "name": name,
        "ok": materialized["ok"],
        "code": materialized["code"],
        "created": not existed,
        "updated": existed,
        "field_count": len(merged_fields),
        "layout_count": len(layout),
        "size": max((field["offset"] + field["size"] for field in layout), default=0),
        "decl": _header_decl_from_layout(name, layout, max((field["offset"] + field["size"] for field in layout), default=0)),
    }


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
def apply_struct_to_many(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    struct_name = str(arguments.get("struct_name") or arguments.get("name") or "").strip()
    items = arguments.get("items", [])
    if not struct_name:
        raise ValueError("struct_name is required")
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list) or not items:
        raise ValueError("items must be a non-empty list")

    results = []
    for item in items:
        kind = str(item.get("kind") or "address").strip().lower()
        try:
            if kind in {"address", "global"}:
                payload = apply_struct({"addr": item.get("addr"), "struct_name": struct_name})
                payload["kind"] = kind
                results.append(payload)
                continue
            if kind == "stack":
                func_ea = _parse_ea(item.get("func_addr") or item.get("addr"))
                results.append(_apply_struct_to_stack(func_ea, item, struct_name))
                continue
            if kind == "local":
                func_ea = _parse_ea(item.get("func_addr") or item.get("addr"))
                local_name = str(item.get("name") or "").strip()
                if not local_name:
                    raise ValueError("local application requires name")
                results.append(_apply_struct_to_local(func_ea, local_name, struct_name))
                continue
            raise ValueError(f"Unsupported kind: {kind}")
        except Exception as exc:
            results.append({"item": item, "struct_name": struct_name, "ok": False, "error": str(exc), "kind": kind})

    ok_count = sum(1 for item in results if item.get("ok"))
    return {"struct_name": struct_name, "count": len(results), "ok_count": ok_count, "items": results}


@idasync
def struct_diff(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    struct_name = str(arguments.get("struct_name") or arguments.get("name") or "").strip()
    if not struct_name:
        raise ValueError("struct_name is required")
    current_tif = _get_named_struct_tinfo(struct_name)
    current_fields = _struct_fields_from_tif(current_tif, include_auto_pad=False)
    reference = _load_struct_reference(arguments)
    reference_fields = [
        field
        for idx, raw in enumerate(reference.get("fields", []))
        for field in [_normalize_struct_field(raw, idx)]
        if not _AUTO_PAD_RE.match(field["name"])
    ]

    current_by_offset = {field["offset"]: field for field in current_fields}
    reference_by_offset = {field["offset"]: field for field in reference_fields}
    offsets = sorted(set(current_by_offset) | set(reference_by_offset))
    added = []
    removed = []
    changed = []
    for offset in offsets:
        current = current_by_offset.get(offset)
        reference_field = reference_by_offset.get(offset)
        if current is None and reference_field is not None:
            added.append(reference_field)
            continue
        if current is not None and reference_field is None:
            removed.append(current)
            continue
        assert current is not None and reference_field is not None
        if current["name"] != reference_field["name"] or current["type"] != reference_field["type"] or current["size"] != reference_field["size"]:
            changed.append({"offset": offset, "current": current, "reference": reference_field})

    current_size = int(current_tif.get_size())
    reference_size = int(reference.get("size") or max((field["offset"] + field["size"] for field in reference_fields), default=0))
    return {
        "struct_name": struct_name,
        "identical": not added and not removed and not changed and current_size == reference_size,
        "current_size": current_size,
        "reference_size": reference_size,
        "added": added,
        "removed": removed,
        "changed": changed,
        "count": len(added) + len(removed) + len(changed) + (0 if current_size == reference_size else 1),
    }


@idasync
def export_struct(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    struct_name = str(arguments.get("struct_name") or arguments.get("name") or "").strip()
    output_format = str(arguments.get("format") or "json").strip().lower()
    path = str(arguments.get("path") or "").strip()
    if not struct_name:
        raise ValueError("struct_name is required")
    tif = _get_named_struct_tinfo(struct_name)
    logical_fields = _struct_fields_from_tif(tif, include_auto_pad=False)
    total_size = int(tif.get_size())
    layout = _build_padded_layout(logical_fields, total_size=total_size)
    payload = {
        "name": struct_name,
        "size": total_size,
        "field_count": len(logical_fields),
        "fields": logical_fields,
        "layout": layout,
        "header": _header_decl_from_layout(struct_name, layout, total_size),
    }
    if path:
        target = _normalize_export_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if output_format in {"h", "header", "c"}:
            target.write_text(payload["header"] + "\n", encoding="utf-8")
        else:
            target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        payload["path"] = str(target)
    return payload


@idasync
def field_xrefs_for_struct(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    struct_name = str(arguments.get("struct_name") or arguments.get("name") or "").strip()
    field_name = str(arguments.get("field") or arguments.get("field_name") or "").strip()
    include_context = _bool_argument(arguments, "include_context", True)
    if not struct_name:
        raise ValueError("struct_name is required")
    tif = _get_named_struct_tinfo(struct_name)
    all_fields = _struct_fields_from_tif(tif, include_auto_pad=False)
    selected_fields = [field for field in all_fields if not field_name or field["name"] == field_name]
    if field_name and not selected_fields:
        raise ValueError(f"Field not found: {struct_name}.{field_name}")
    rows = []
    for field in selected_fields:
        refs_payload = xrefs_to_field({"queries": [{"struct": struct_name, "field": field["name"]}]})[0]
        xrefs = refs_payload.get("xrefs") or []
        if include_context:
            enriched = []
            for xref in xrefs:
                xea = _parse_ea(xref["address"])
                line = ida_lines.tag_remove(ida_lines.generate_disasm_line(xea, 0) or "")
                enriched.append({**xref, **_classify_xref_access(xea), "text": line, "segment": _segment_name(xea)})
            xrefs = enriched
        rows.append(
            {
                "struct": struct_name,
                "field": field["name"],
                "offset": _hex(field["offset"]),
                "type": field["type"],
                "count": len(xrefs),
                "xrefs": xrefs,
            }
        )
    return {"struct_name": struct_name, "field_count": len(rows), "fields": rows}


@idasync
def typed_decompile_export(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    ea = _parse_ea(arguments.get("addr"))
    include_line_map = _bool_argument(arguments, "include_line_map", False)
    output_format = str(arguments.get("format") or "json").strip().lower()
    path = str(arguments.get("path") or "").strip()
    decomp = decompile({"addr": ea, "fallback": arguments.get("fallback", "disasm"), "max_instructions": arguments.get("max_instructions", 400)})
    payload = {
        "addr": decomp.get("addr"),
        "name": decomp.get("name"),
        "mode": decomp.get("mode"),
        "code": decomp.get("code") or "",
    }
    if decomp.get("decompile_error"):
        payload["decompile_error"] = decomp.get("decompile_error")
    if decomp.get("instructions"):
        payload["instructions"] = decomp.get("instructions")
    if include_line_map:
        payload["line_map"] = _decompile_line_map_payload(ea)
    if path:
        target = _normalize_export_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if output_format in {"txt", "text", "c"}:
            text = str(payload.get("code") or "")
            if not text and payload.get("decompile_error"):
                text = f"/* Hex-Rays failed: {_c_comment_text(payload.get('decompile_error'))} */"
            if include_line_map:
                text += "\n\n/* line_map */\n" + json.dumps(payload["line_map"], ensure_ascii=False, indent=2)
            target.write_text(text + "\n", encoding="utf-8")
        else:
            target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        payload["path"] = str(target)
    return payload


@idasync
def export_decompiled_c(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    include_extern = bool(arguments.get("include_extern", False))
    include_thunks = bool(arguments.get("include_thunks", False))
    filt = str(arguments.get("filter", "") or "").lower()
    fallback = str(arguments.get("fallback") or "comment").strip().lower()
    if fallback not in {"comment", "none", "disasm", "asm"}:
        raise ValueError("fallback must be one of: comment, none, disasm, asm")
    max_functions = max(0, int(arguments.get("max_functions", 0) or 0))
    return_code = _bool_argument(arguments, "return_code", False)
    max_return_bytes = max(0, int(arguments.get("max_return_bytes", 256 * 1024) or 0))
    path = str(arguments.get("path") or "").strip()
    if not path:
        idb_path = idc.get_idb_path() or "ida_export.i64"
        path = str(Path(idb_path).with_suffix(".c"))

    eligible_functions: list[tuple[int, dict[str, Any]]] = []
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
        eligible_functions.append((int(func.start_ea), item))

    eligible_functions.sort(key=lambda pair: (pair[1]["segment"].lower() == "extern", pair[0]))
    functions: list[tuple[int, dict[str, Any]]] = []
    for ea, item in eligible_functions:
        if filt and filt not in item["name"].lower() and filt not in item["address"].lower():
            continue
        functions.append((ea, item))
    selected_pairs = functions[:max_functions] if max_functions else functions
    selected = [item for _ea, item in selected_pairs]

    if not selected:
        return {
            "ok": False,
            "complete": False,
            "mode": "export_decompiled_c",
            "path": str(_normalize_export_path(path)),
            "bytes_written": 0,
            "function_total": len(eligible_functions),
            "matched_count": len(functions),
            "selected_count": 0,
            "decompiled_count": 0,
            "fallback_count": 0,
            "failed_count": 0,
            "exported_count": 0,
            "include_extern": include_extern,
            "include_thunks": include_thunks,
            "filter": filt,
            "fallback": fallback,
            "max_functions": max_functions,
            "error": "export_decompiled_c selected zero functions",
            "hint": "filter is a simple case-insensitive substring match against function name or 0x address. Omit filter to export all eligible functions; use max_functions to cap size.",
            "next_steps": [
                "Retry export_decompiled_c without filter for full-IDB export.",
                "Use lookup_funcs or list_functions to confirm the exact function name/address before filtering.",
                "Do not manually assemble a .c file by copying individual decompile results unless export_decompiled_c is unavailable.",
            ],
            "sample_functions": [item for _ea, item in eligible_functions[:20]],
        }

    exported: list[dict[str, Any]] = []
    fallbacks: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    target = _normalize_export_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    code_parts: list[str] = []
    returned_bytes = 0

    def emit(handle, line: str = "") -> None:
        nonlocal returned_bytes
        text = line + "\n"
        handle.write(text)
        if return_code and (max_return_bytes <= 0 or returned_bytes < max_return_bytes):
            encoded_len = len(text.encode("utf-8"))
            if max_return_bytes <= 0 or returned_bytes + encoded_len <= max_return_bytes:
                code_parts.append(text)
                returned_bytes += encoded_len

    with target.open("w", encoding="utf-8", newline="\n") as handle:
        emit(handle, "/*")
        emit(handle, " * IDA decompiled C export")
        emit(handle, f" * input: {_c_comment_text(ida_nalt.get_root_filename() or '')}")
        emit(handle, f" * idb: {_c_comment_text(idc.get_idb_path() or '')}")
        emit(handle, f" * functions: {len(selected)} / {len(functions)}")
        emit(handle, " */")
        emit(handle)

        for item in selected:
            addr = item["address"]
            name = item["name"]
            emit(handle, f"/* ===== {_c_comment_text(name or '<unnamed>')} @ {addr} ===== */")
            try:
                decomp = decompile({"addr": addr, "fallback": "disasm" if fallback in {"disasm", "asm"} else "none"})
                if decomp.get("mode") == "decompile" and decomp.get("code"):
                    emit(handle, str(decomp["code"]).rstrip())
                    exported.append({"addr": addr, "name": name, "mode": "decompile"})
                elif fallback in {"disasm", "asm"}:
                    emit(handle, "/*")
                    emit(handle, f" * Hex-Rays failed: {_c_comment_text(decomp.get('decompile_error') or 'unavailable')}")
                    for insn in decomp.get("instructions") or []:
                        emit(handle, f" * {insn.get('address', '')}: {_c_comment_text(insn.get('text', ''))}")
                    emit(handle, " */")
                    fallbacks.append({"addr": addr, "name": name, "mode": "disasm", "error": str(decomp.get("decompile_error") or "")})
                else:
                    error = str(decomp.get("decompile_error") or "Hex-Rays decompile failed")
                    emit(handle, f"/* Hex-Rays failed: {_c_comment_text(error)} */")
                    failed.append({"addr": addr, "name": name, "error": error})
            except Exception as exc:
                error = str(exc)
                emit(handle, f"/* export failed: {_c_comment_text(error)} */")
                failed.append({"addr": addr, "name": name, "error": error})
            emit(handle)

    file_size = target.stat().st_size
    payload = {
        "ok": bool(exported),
        "complete": bool(len(failed) == 0 and len(fallbacks) == 0),
        "mode": "export_decompiled_c",
        "path": str(target),
        "bytes_written": file_size,
        "function_total": len(eligible_functions),
        "matched_count": len(functions),
        "selected_count": len(selected),
        "decompiled_count": len(exported),
        "fallback_count": len(fallbacks),
        "failed_count": len(failed),
        "exported_count": len(exported) + len(fallbacks),
        "fallbacks": fallbacks[:100],
        "failed": failed[:100],
        "truncated_fallbacks": max(0, len(fallbacks) - 100),
        "truncated_failures": max(0, len(failed) - 100),
        "include_extern": include_extern,
        "include_thunks": include_thunks,
        "filter": filt,
        "fallback": fallback,
        "max_functions": max_functions,
    }
    if return_code:
        payload["code"] = "".join(code_parts)
        payload["code_truncated"] = max_return_bytes > 0 and returned_bytes < file_size
        payload["max_return_bytes"] = max_return_bytes
    return payload


@idasync
def type_workflow(arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    arguments = arguments or {}
    results: dict[str, Any] = {
        "decls": [],
        "structs": [],
        "applies": [],
        "exports": [],
        "typed_decompile": [],
    }

    for decl in arguments.get("decls", []) or []:
        try:
            payload = declare_type({"decls": [decl]})
            results["decls"].append(payload[0] if isinstance(payload, list) and payload else {"ok": False, "decl": decl})
        except Exception as exc:
            results["decls"].append({"ok": False, "decl": decl, "error": str(exc)})

    for item in arguments.get("structs", []) or []:
        mode = str(item.get("mode") or "upsert").strip().lower()
        try:
            if mode in {"padded", "map", "from_map"}:
                results["structs"].append(create_padded_struct_from_map(item))
            elif mode in {"create"}:
                results["structs"].append(create_struct(item))
            else:
                results["structs"].append(upsert_struct(item))
        except Exception as exc:
            results["structs"].append({"ok": False, "name": item.get("name"), "mode": mode, "error": str(exc)})

    for item in arguments.get("applies", []) or []:
        try:
            if item.get("struct_name"):
                results["applies"].append(
                    apply_struct_to_many(
                        {
                            "struct_name": item.get("struct_name"),
                            "items": item.get("items") or [],
                        }
                    )
                )
            elif item.get("decl") or item.get("signature"):
                edits = item.get("edits")
                if edits:
                    results["applies"].append({"kind": "decl_batch", "items": set_type({"edits": edits})})
                else:
                    results["applies"].append(apply_decl(item))
            elif item.get("edits"):
                results["applies"].append({"kind": "type_batch", "items": set_type({"edits": item.get("edits")})})
            else:
                raise ValueError("Unsupported apply workflow item")
        except Exception as exc:
            results["applies"].append({"ok": False, "item": item, "error": str(exc)})

    for item in arguments.get("exports", []) or []:
        try:
            results["exports"].append(export_struct(item))
        except Exception as exc:
            results["exports"].append({"ok": False, "name": item.get("struct_name") or item.get("name"), "error": str(exc)})

    for item in arguments.get("typed_decompile", []) or []:
        try:
            results["typed_decompile"].append(typed_decompile_export(item))
        except Exception as exc:
            results["typed_decompile"].append({"ok": False, "addr": item.get("addr"), "error": str(exc)})

    results["ok"] = all(
        _workflow_entries_ok(group)
        for _group_name, group in results.items()
        if isinstance(group, list)
    )
    results["changed_count"] = (
        _workflow_entries_changed(results["decls"])
        + _workflow_entries_changed(results["structs"])
        + _workflow_entries_changed(results["applies"])
    )
    results["db_changed"] = results["changed_count"] > 0
    return results


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
    {"name": "rename", "description": "Rename functions, globals, local variables, or stack variables."},
    {"name": "set_comments", "description": "Set comments at addresses."},
    {"name": "set_type", "description": "Apply C declarations or types to addresses."},
    {"name": "apply_decl", "description": "Apply a C declaration to a symbol/address like the GUI Y command."},
    {"name": "reanalyze_function", "description": "Create/reanalyze the function containing an address."},
    {"name": "create_struct", "description": "Create a named struct type from field definitions."},
    {"name": "upsert_struct", "description": "Create or update a named struct type from offset-preserving field definitions."},
    {"name": "create_padded_struct_from_map", "description": "Create a struct from {offset,name,type} field maps with automatic padding members."},
    {"name": "apply_struct", "description": "Apply a named struct type at an address."},
    {"name": "apply_struct_to_many", "description": "Apply a named struct type to many addresses, stack variables, or local variables."},
    {"name": "struct_diff", "description": "Compare the current IDA struct definition against an exported header/json reference."},
    {"name": "export_struct", "description": "Export a named struct as canonical header text or json."},
    {"name": "field_xrefs_for_struct", "description": "Return per-field xrefs for a struct with contextual disassembly."},
    {"name": "typed_decompile_export", "description": "Export decompiled code for a function under the current typed DB state."},
    {"name": "export_decompiled_c", "description": "Export all or filtered functions from the current IDB as one .c file. Prefer this over manually copying per-function decompile output; filter is a simple substring on function name/address."},
    {"name": "type_workflow", "description": "LLM-friendly high-level workflow for declaring types, upserting structs, applying them, exporting them, and exporting typed decompilation."},
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
    "upsert_struct": upsert_struct,
    "create_padded_struct_from_map": create_padded_struct_from_map,
    "apply_struct": apply_struct,
    "apply_struct_to_many": apply_struct_to_many,
    "struct_diff": struct_diff,
    "export_struct": export_struct,
    "field_xrefs_for_struct": field_xrefs_for_struct,
    "typed_decompile_export": typed_decompile_export,
    "export_decompiled_c": export_decompiled_c,
    "type_workflow": type_workflow,
    "make_array": make_array,
    "save_database": save_database,
}


def call_tool(tool_name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    handler = TOOL_HANDLERS.get(tool_name)
    if handler is None:
        raise ValueError(f"Unknown tool: {tool_name}")
    return _tool_result(handler(arguments))
