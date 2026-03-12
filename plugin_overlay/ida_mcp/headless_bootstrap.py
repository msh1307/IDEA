import json
import os
import sys

import idc


def main():
    if len(idc.ARGV) < 2:
        print("[MCP] headless bootstrap requires a JSON config path")
        return

    config_path = idc.ARGV[1]
    with open(config_path, "r", encoding="utf-8") as fh:
        config = json.load(fh)

    if config.get("manager_url"):
        os.environ["IDA_MCP_MANAGER_URL"] = config["manager_url"]
    os.environ.setdefault("IDA_MCP_REGISTER_WITH_MANAGER", "0")

    plugin_root = config["plugin_root"]
    if plugin_root not in sys.path:
        sys.path.insert(0, plugin_root)

    from ida_mcp.runtime import IdaMcpRuntime

    runtime = IdaMcpRuntime()
    runtime.start(
        config.get("host", "0.0.0.0"),
        int(config["port"]),
        background=False,
        engine="headless",
        launch_token=config.get("launch_token"),
    )


if __name__ == "__main__":
    main()
