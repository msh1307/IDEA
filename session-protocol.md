# Session Protocol

This document defines the internal protocol between the hybrid manager and its adapters.

The public MCP surface can be implemented separately, but the internal contract should remain stable.

## Session Record

```json
{
  "session_id": "gui-3e8f3d71",
  "engine": "gui",
  "display_name": "notepad.exe",
  "binary_path": "C:\\Users\\msh\\samples\\notepad.exe",
  "binary_hash": "sha256:3b8d...",
  "idb_path": "C:\\Users\\msh\\samples\\notepad.i64",
  "status": "ready",
  "source": "plugin_discovered",
  "capabilities": [
    "decompile",
    "get_function",
    "list_xrefs",
    "rename_symbol",
    "set_comment",
    "patch_bytes",
    "jump_to_address"
  ],
  "endpoint": {
    "transport": "http",
    "url": "http://127.0.0.1:18111"
  },
  "owner_pid": 11832,
  "last_seen": "2026-03-12T12:00:00Z",
  "current": false
}
```

## Plugin Registration

GUI sessions should self-register with the manager.

### `register_session`

```json
{
  "message_type": "register_session",
  "session": {
    "engine": "gui",
    "display_name": "sample.exe",
    "binary_path": "C:\\Users\\msh\\samples\\sample.exe",
    "binary_hash": "sha256:abcd1234",
    "idb_path": "C:\\Users\\msh\\samples\\sample.i64",
    "status": "ready",
    "capabilities": [
      "decompile",
      "get_function",
      "list_xrefs",
      "rename_symbol",
      "set_comment",
      "patch_bytes",
      "jump_to_address"
    ],
    "owner_pid": 11832,
    "metadata": {
      "ida_version": "9.x",
      "plugin_version": "0.x",
      "readonly": false
    }
  }
}
```

Manager response:

```json
{
  "ok": true,
  "session_id": "gui-3e8f3d71",
  "heartbeat_interval_sec": 10
}
```

### `heartbeat`

```json
{
  "message_type": "heartbeat",
  "session_id": "gui-3e8f3d71",
  "status": "ready",
  "current_address": "0x140001000",
  "current_function": "sub_140001000",
  "busy": false,
  "opened_at": "2026-03-12T11:58:00Z"
}
```

### `unregister_session`

```json
{
  "message_type": "unregister_session",
  "session_id": "gui-3e8f3d71",
  "reason": "idb_closed"
}
```

## Headless Worker Registration

Headless workers are usually manager-created, but they should still register through the same contract.

### `register_session`

```json
{
  "message_type": "register_session",
  "session": {
    "engine": "headless",
    "display_name": "sample.exe",
    "binary_path": "C:\\Users\\msh\\samples\\sample.exe",
    "binary_hash": "sha256:abcd1234",
    "idb_path": "C:\\Users\\msh\\samples\\sample.i64",
    "status": "ready",
    "capabilities": [
      "decompile",
      "get_function",
      "list_xrefs",
      "rename_symbol",
      "set_comment",
      "patch_bytes"
    ],
    "owner_pid": 18760,
    "metadata": {
      "worker_version": "0.x",
      "readonly": false
    }
  }
}
```

## Public MCP Tools

These are the recommended user-facing tools.

### `list_alive_sessions`

Returns live or attachable sessions:

```json
{
  "sessions": [
    {
      "session_id": "gui-3e8f3d71",
      "engine": "gui",
      "display_name": "sample.exe",
      "status": "ready",
      "current": true
    },
    {
      "session_id": "headless-7f8ad201",
      "engine": "headless",
      "display_name": "second_sample.exe",
      "status": "ready",
      "current": false
    }
  ]
}
```

### `select_session`

Input:

```json
{
  "session_id": "gui-3e8f3d71"
}
```

Output:

```json
{
  "ok": true,
  "current_session_id": "gui-3e8f3d71"
}
```

### `current_session`

Output:

```json
{
  "session_id": "gui-3e8f3d71",
  "engine": "gui",
  "display_name": "sample.exe",
  "status": "ready",
  "capabilities": [
    "decompile",
    "get_function",
    "list_xrefs",
    "rename_symbol",
    "set_comment",
    "patch_bytes",
    "jump_to_address"
  ]
}
```

### `open_binary`

Input:

```json
{
  "path": "/mnt/c/Users/msh/samples/sample.exe",
  "mode": "auto",
  "reuse": true
}
```

Output:

```json
{
  "ok": true,
  "session_id": "headless-7f8ad201",
  "engine": "headless",
  "status": "ready",
  "selected": true
}
```

Routing rules:

- `mode=headless`: always create or reuse a headless worker
- `mode=gui`: launch GUI or attach to a matching GUI session
- `mode=auto`: prefer GUI reuse, otherwise headless

### `attach_to_gui`

Input:

```json
{
  "filter": {
    "binary_name": "sample.exe"
  }
}
```

Output:

```json
{
  "matches": [
    {
      "session_id": "gui-3e8f3d71",
      "display_name": "sample.exe",
      "status": "ready"
    }
  ],
  "auto_selected": true,
  "current_session_id": "gui-3e8f3d71"
}
```

### `close_session`

Input:

```json
{
  "session_id": "headless-7f8ad201",
  "save": true
}
```

Output:

```json
{
  "ok": true,
  "closed_session_id": "headless-7f8ad201"
}
```

## Invoke Contract

Analysis tools should be routed through a normalized backend call.

### Manager side request

```json
{
  "tool": "decompile",
  "args": {
    "address": "0x140001000"
  },
  "session_id": "gui-3e8f3d71"
}
```

### Adapter response

```json
{
  "ok": true,
  "engine": "gui",
  "session_id": "gui-3e8f3d71",
  "result": {
    "function_name": "sub_140001000",
    "address": "0x140001000",
    "pseudocode": "int __fastcall sub_140001000(...) { ... }"
  }
}
```

### Error response

```json
{
  "ok": false,
  "engine": "headless",
  "session_id": "headless-7f8ad201",
  "error": {
    "code": "CAPABILITY_MISSING",
    "message": "capture_graph is not available for headless sessions"
  }
}
```

## Auto-Selection Rules

Recommended default order:

1. reuse explicit `session_id` if provided and alive
2. reuse current session if alive
3. reuse exact `binary_hash` match
4. if exactly one candidate is alive, auto-select it
5. otherwise return candidates and require selection

## Health Rules

- heartbeat interval: 10 seconds
- `stale` after 30 seconds without heartbeat
- `dead` after transport failure plus no heartbeat
- headless idle timeout: 15 to 30 minutes

Do not auto-select `stale` sessions.

## Locking Rules

Before opening a writable session:

1. check existing sessions with the same `binary_hash`
2. if a writable GUI session exists, deny writable headless open
3. if a writable headless session exists, deny GUI auto-open unless promoting or cloning

Manager error example:

```json
{
  "ok": false,
  "error": {
    "code": "SESSION_CONFLICT",
    "message": "sample.i64 is already open in writable GUI session gui-3e8f3d71"
  }
}
```

## Path Translation

Manager should normalize paths before registry insertion.

Canonical example:

```json
{
  "input_path": "/mnt/c/Users/msh/samples/sample.exe",
  "canonical_windows_path": "C:\\Users\\msh\\samples\\sample.exe",
  "canonical_wsl_path": "/mnt/c/Users/msh/samples/sample.exe"
}
```

Adapters should receive the path format native to their runtime environment.

## Correlation for Manager-Launched GUI Sessions

When the manager launches GUI IDA, it should include a launch token.

Example:

```json
{
  "pending_launch_id": "launch-f0b84c0a",
  "path": "C:\\Users\\msh\\samples\\sample.i64",
  "requested_engine": "gui"
}
```

The plugin registration should echo the token if possible.

If not possible, correlate by:

- owner PID
- path
- registration time window

## v1 Scope

Keep the first implementation narrow:

- session registration
- heartbeats
- alive session listing
- selection
- headless open
- tool routing for core read and write actions

Leave these for later:

- debugger integration
- graph screenshots
- cursor sync
- collaborative multi-client session control
