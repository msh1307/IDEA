# Install

## 1. WSL manager

```bash
git clone <repo-url>
cd IDEA
./scripts/install_wsl.sh
```

This creates `.venv` and installs the manager in editable mode.
It also updates the Codex MCP config for the current WSL user and the detected
Windows user at `.codex/config.toml`.
The detected Windows host IP is written into the generated MCP entry.

## 2. Windows IDA plugin overlay

Open PowerShell on Windows:

```powershell
cd <repo>\IDEA
.\scripts\install_plugin.ps1
```

Default target:

- `C:\Users\<user>\AppData\Roaming\Hex-Rays\IDA Pro\plugins`

What it does:

- optionally backs up the current `ida_mcp` plugin files
- installs the bundled `ida_mcp` loader and package from `plugin_overlay/`
- replaces any previous `ida_mcp` install in the target directory

Notes:

- If your plugin directory is not `%APPDATA%\Hex-Rays\IDA Pro\plugins`, pass `-PluginRoot`.

## 3. Run the manager

From WSL:

```bash
cd IDEA
./scripts/run_manager.sh
```

Daemon endpoint:

- health API: `http://127.0.0.1:18080/healthz`

Normal Codex usage:

- Codex does not talk to the daemon directly.
- Codex still starts the normal MCP entrypoint with `--transport stdio`.
- That stdio shim checks `127.0.0.1:18080`, reuses the daemon if it exists,
  or starts it if it does not.
- Multiple agents can share the same daemon and session registry.

Current behavior:

- `list_alive_sessions` is shared across agents
- `current_session` is tracked per client
- headless launches are daemon-owned
- `write_session_tool_output` writes results into WSL paths

## 4. Quick smoke test

From WSL:

```bash
./scripts/smoke_test_headless.sh
```

## Notes

- The manager package is meant to be installed from Git like a normal Python project.
- The plugin bundle is self-contained and no longer depends on a pre-existing `ida_mcp` install.
- If your Codex or local MCP config already pins the correct Windows host path, keep using that. The code still keeps fallback probes because WSL networking is inconsistent across systems.
- The shared daemon uses a fixed port and a lock file at `/tmp/ida-hybrid-manager-daemon.lock`.
- The default IDA install root used by the launcher is `C:\Program Files\IDA Professional 9.3`. Override with `IDA_INSTALL_ROOT` if needed.
- Codex MCP configs are not hot-reloaded. Restart Codex after `config.toml` changes.
- If IDA was already open when you patched the plugin, restart IDA or reopen the IDB.
