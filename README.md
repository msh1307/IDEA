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

- The Windows overlay patches an existing `ida_mcp` install. It does not do a fresh plugin install.
- If your plugin directory is non-standard, pass `-PluginRoot` to `install_plugin.ps1`.

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

## Test

```bash
cd IDEA
./scripts/smoke_test_headless.sh
```

## Restart

- If Codex was already running when `config.toml` changed, restart Codex. MCP servers are not hot-reloaded.
- If IDA was already open when the overlay changed, restart IDA or reopen the IDB.

Useful tools:

- `open_binary`
- `close_session`
- `list_alive_sessions`
- `call_session_tool`
- `write_session_tool_output`

## Config example

- [examples/codex-mcp-config.toml](examples/codex-mcp-config.toml)

## Files

- manager: [src/ida_hybrid_manager](src/ida_hybrid_manager)
- plugin overlay: [plugin_overlay](plugin_overlay)
- config installer: [scripts/install_codex_config.py](scripts/install_codex_config.py)
- install notes: [INSTALL.md](INSTALL.md)
