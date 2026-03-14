# IDA Hybrid Manager

## Install

WSL:

```bash
git clone <repo-url>
cd ida-hybrid-manager
./scripts/install_wsl.sh
```

Windows PowerShell:

```powershell
cd <repo>\ida-hybrid-manager
.\scripts\install_plugin.ps1
```

## Run

WSL:

```bash
cd ida-hybrid-manager
./scripts/run_manager.sh
```

What runs now:

- one shared daemon on `127.0.0.1:18080`
- Codex/agents connect through the normal MCP `stdio` entrypoint
- the `stdio` client auto-reuses the daemon, or starts it if missing

## Test

```bash
cd ida-hybrid-manager
./scripts/smoke_test_headless.sh
```

Useful tools:

- `open_binary`
- `close_session`
- `list_alive_sessions`
- `call_session_tool`
- `write_session_tool_output`

## Config example

- [examples/codex-mcp-config.toml](/root/ida-hybrid-manager/examples/codex-mcp-config.toml)

## Files

- manager: [src/ida_hybrid_manager](/root/ida-hybrid-manager/src/ida_hybrid_manager)
- plugin overlay: [plugin_overlay](/root/ida-hybrid-manager/plugin_overlay)
- install notes: [INSTALL.md](/root/ida-hybrid-manager/INSTALL.md)
