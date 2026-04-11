# IDA Hybrid Manager

## Install

WSL:

```bash
git clone <repo-url>
cd IDEA
./scripts/install_wsl.sh
```

This creates `.venv`, installs the manager in editable mode, and updates the
Codex MCP config for the current WSL user plus the detected Windows user.
The installer now auto-detects both the Windows host IP and the IDA install root
and writes them into the generated MCP entry.

Windows PowerShell:

```powershell
cd <repo>\IDEA
.\scripts\install_plugin.ps1
```

Defaults:

- IDA install root: `C:\Program Files\IDA Professional 9.3`
- plugin target: `%APPDATA%\Hex-Rays\IDA Pro\plugins`

Notes:

- The Windows installer installs the native `idea_ida` GUI plugin bundle.
- If your plugin directory is non-standard, pass `-PluginRoot` to `install_plugin.ps1`.
- Headless sessions now advertise the WSL-reachable Windows host IP by default; override with `IDA_MCP_CONNECT_HOST` if needed.
- The WSL installer writes both `IDA_MCP_CONNECT_HOST` and `IDA_INSTALL_ROOT` into the generated Codex config.
- Manager-owned headless launches can bootstrap from the repo's bundled `plugin_overlay/idea_ida_backend` even if the Windows plugin has not been installed yet.
- GUI attach/open still requires the Windows plugin install because GUI session registration happens inside IDA.

## Run

WSL:

```bash
cd IDEA
./scripts/run_manager.sh
```

What runs now:

- one shared daemon on `127.0.0.1:18080`
- Codex/agents connect through the normal MCP `stdio` entrypoint
- the `stdio` client auto-reuses the daemon, or starts it if missing
- the generated Codex config now launches the stdio entrypoint directly, without a shell wrapper

## Test

```bash
cd IDEA
./scripts/smoke_test_headless.sh
./.venv/bin/python scripts/smoke_test_stdio.py "/mnt/c/Users/USER/Downloads/for_user (48)/deploy/board_server"
```

## Restart

- If Codex was already running when `config.toml` changed, restart Codex. MCP servers are not hot-reloaded.
- If IDA was already open when the plugin changed, restart IDA or reopen the IDB.

Useful tools:

- `inspect_environment`
- `inspect`
- `read`
- `search`
- `xrefs`
- `define`
- `open_binary`
- `close_session`
- `list_alive_sessions`
- `call_session_tool`
- `write_session_tool_output`
- Tools that accept `session_id` will target that explicit session when provided; if omitted, they run against the current selected session for the client.
- There is no implicit "only live session" auto-pick anymore. If no `session_id` is supplied, the client must already have selected a current session.
- `open_binary(..., reuse=true)` is the default fast path. Use `remove_previous_idb=true` only when you want a fresh launch that ignores and deletes the adjacent saved `.i64`.
- For `write_session_tool_output`, prefer `/mnt/c/...` output paths. `C:\...` inputs are normalized to WSL paths before writing.
- If the original input binary already has an adjacent `.i64`, headless staging copies that database too and reuses it.
- When a manager-owned headless session is closed with `save=true`, the staged `.i64` is copied back next to the original binary path by default.
- backend raw tools now include `decompile`, `disasm`, `get_xrefs_to`, `get_xrefs_from`, `list_strings`, `find_bytes`, `find_text`, `find_immediates`, `find_insns`, `get_data_item`, `read_bytes`, `read_byte`, `read_word`, `read_dword`, `read_qword`, `read_array`, `hex_dump`, `set_type`, `create_struct`, `apply_struct`, and `make_array`
- Session-bearing responses now expose a canonical `revision` block:
  `txid`, `snapshot_txid`, `requires_refresh`, `attached_client_count`, `last_writer_client_id`
- Raw backend tool results now use `content` as a short summary and keep full payloads in `structuredContent` to avoid duplicating large responses like decompilation text.
- Public MCP tool results always expose `structuredContent` as an object. If the underlying payload is a list or scalar, it is wrapped as `structuredContent.result`.
- Tool-result metadata also uses `revision` as the canonical session state block instead of repeating flat session revision fields.
- High-level analysis tools now treat `full=true` (or `detail="full"`) as the common expansion switch. Defaults stay slim; `full` opts into heavier fields such as line maps or raw member bytes when supported by the tool.
- Mutating tool calls can pass `expected_txid` to reject stale writes and `force=true` to suppress stale warnings when best-effort continuation is intended.
- `close_session(..., force=true)` bypasses attached-client / in-flight-op guards and should be reserved for explicit teardown.
- `type_workflow` now reports `db_changed` and `changed_count`, so partial-success workflows can still advance session revision while all-failure workflows do not.

High-level API:

- prefer `inspect`, `read`, `search`, `xrefs`, and `define` for normal usage
- older fine-grained tools remain available as compatibility paths

## Config example

- [examples/codex-mcp-config.toml](examples/codex-mcp-config.toml)

## Files

- manager: [src/ida_hybrid_manager](src/ida_hybrid_manager)
- native IDA plugin: [plugin_overlay/idea_ida.py](plugin_overlay/idea_ida.py) and [plugin_overlay/idea_ida_backend](plugin_overlay/idea_ida_backend)
- config installer: [scripts/install_codex_config.py](scripts/install_codex_config.py)
- install notes: [INSTALL.md](INSTALL.md)
