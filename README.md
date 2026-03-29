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

Windows PowerShell:

```powershell
cd <repo>\IDEA
.\scripts\install_plugin.ps1
```

Defaults:

- IDA install root: `C:\Program Files\IDA Professional 9.3`
- plugin target: `%APPDATA%\Hex-Rays\IDA Pro\plugins`

Notes:

- The Windows installer now installs a self-contained `idea_ida` plugin bundle.
- If your plugin directory is non-standard, pass `-PluginRoot` to `install_plugin.ps1`.
- Headless sessions now advertise the WSL-reachable Windows host IP by default; override with `IDA_MCP_CONNECT_HOST` if needed.

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

- `open_binary`
- `close_session`
- `list_alive_sessions`
- `call_session_tool`
- `write_session_tool_output`
- backend raw tools now include `decompile`, `disasm`, `get_xrefs_to`, `get_xrefs_from`, `list_strings`, `find_bytes`, `find_text`, `find_immediates`, `find_insns`, `get_data_item`, `read_bytes`, `read_byte`, `read_word`, `read_dword`, `read_qword`, `read_array`, `hex_dump`, `set_type`, `create_struct`, `apply_struct`, and `make_array`

## Config example

- [examples/codex-mcp-config.toml](examples/codex-mcp-config.toml)

## Files

- manager: [src/ida_hybrid_manager](src/ida_hybrid_manager)
- native IDA plugin: [plugin_overlay/idea_ida.py](plugin_overlay/idea_ida.py) and [plugin_overlay/idea_ida_backend](plugin_overlay/idea_ida_backend)
- config installer: [scripts/install_codex_config.py](scripts/install_codex_config.py)
- install notes: [INSTALL.md](INSTALL.md)
