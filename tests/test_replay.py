import unittest

from ida_hybrid_manager.replay import _architecture, replay_snapshot


def _snapshot(code: bytes, *, data: bytes | None = None) -> dict:
    memory = [{"start": "0x1000", "data": code.hex(), "perm": "rx"}]
    if data is not None:
        memory.append({"start": "0x2000", "data": data.hex(), "perm": "rw"})
    return {
        "entry": "0x1000",
        "architecture": {"name": "x86", "bits": 64, "endian": "little"},
        "abi": "sysv64",
        "memory": memory,
    }


class ReplayTests(unittest.TestCase):
    def test_ida_arm_processor_with_64_bit_database_is_arm64(self) -> None:
        self.assertEqual(
            _architecture({"architecture": {"name": "arm", "bits": 64, "endian": "little"}}),
            ("arm64", 64, "little"),
        )

    def test_function_replay(self) -> None:
        result = replay_snapshot(_snapshot(bytes.fromhex("89f8ffc0c3")), {"args": [41]}, max_steps=20)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["stop_reason"], "return")
        self.assertEqual(result["registers"]["RAX"], "0x2A")

    def test_memory_patch_changes_result(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("8b07c3"), data=(7).to_bytes(4, "little") + b"\0" * 4092),
            {"args": [0x2000], "memory_patches": [{"addr": "0x2000", "data": "2a000000"}]},
            max_steps=20,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["registers"]["RAX"], "0x2A")
        self.assertEqual(result["patches_failed"], [])

    def test_unmapped_read_is_reported(self) -> None:
        result = replay_snapshot(_snapshot(bytes.fromhex("8b07c3")), {"args": [0x3000]}, max_steps=20)
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "memory_fault")
        self.assertEqual(result["fault"]["kind"], "read")
        self.assertEqual(result["fault"]["addr"], "0x3000")
        self.assertEqual(result["suggested_regions"], [{"addr": "0x3000", "size": 4096, "perm": "r"}])

    def test_explicit_stack_pointer_does_not_hide_missing_stack_page(self) -> None:
        snapshot = _snapshot(bytes.fromhex("8b0424c3"))
        snapshot["registers"] = {"RSP": "0x3000"}
        result = replay_snapshot(snapshot, {}, max_steps=20)
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "memory_fault")
        self.assertEqual(result["fault"]["kind"], "read")
        self.assertEqual(result["fault"]["addr"], "0x3000")

    def test_read_only_page_reports_write_fault(self) -> None:
        result = replay_snapshot(
            {
                "entry": "0x1000",
                "architecture": {"name": "x86", "bits": 64, "endian": "little"},
                "abi": "sysv64",
                "memory": [
                    {"start": "0x1000", "data": "c60701c3", "perm": "rx"},
                    {"start": "0x2000", "data": "00", "perm": "r"},
                ],
            },
            {"args": [0x2000]},
            max_steps=20,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "memory_fault")
        self.assertEqual(result["fault"]["kind"], "write")
        self.assertEqual(result["fault"]["addr"], "0x2000")

    def test_skip_hook_replaces_syscall_and_sets_return_value(self) -> None:
        snapshot = _snapshot(bytes.fromhex("0f05c3"))
        result = replay_snapshot(
            snapshot,
            {
                "hooks": [
                    {
                        "id": "fake-syscall",
                        "addr": "0x1000",
                        "action": "skip",
                        "size": 2,
                        "registers": {"RAX": "0x1234"},
                    }
                ]
            },
            max_steps=20,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["stop_reason"], "return")
        self.assertEqual(result["registers"]["RAX"], "0x1234")
        self.assertEqual(result["hooks_applied"][0]["id"], "fake-syscall")

    def test_thumb_entry_and_return_use_thumb_pc(self) -> None:
        result = replay_snapshot(
            {
                "entry": "0x1000",
                "architecture": {"name": "arm", "bits": 32, "endian": "little", "mode": "thumb"},
                "memory": [{"start": "0x1000", "data": "2a207047", "perm": "rx"}],
            },
            {},
            max_steps=20,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["stop_reason"], "return")

    def test_hook_memory_write_replays_output_buffer(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("0f058b07c3"), data=b"\0" * 4096),
            {
                "args": [0x2000],
                "hooks": [{
                    "addr": "0x1000",
                    "action": "skip",
                    "size": 2,
                    "writes": [{"addr": "0x2000", "data": "2a000000"}],
                }],
            },
            max_steps=20,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["registers"]["RAX"], "0x2A")
        self.assertEqual(result["hooks_applied"][0]["writes"][0]["size"], 4)

    def test_readback_returns_final_buffer_contents(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("c6072a0fb607c3"), data=b"\0" * 4096),
            {"args": [0x2000], "readback": [{"addr": "0x2000", "size": 4}]},
            max_steps=20,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["registers"]["RAX"], "0x2A")
        self.assertEqual(result["memory_after"][0]["data"], "2a000000")

    def test_inspect_checkpoint_returns_selected_registers_and_memory(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("c6072a0fb607c3"), data=b"\0" * 4096),
            {
                "args": [0x2000],
                "inspect": [{
                    "at": "0x1003",
                    "registers": ["RAX", "RDI"],
                    "memory": [{"addr": "0x2000", "size": 1}],
                }],
            },
            max_steps=20,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["observations"][0]["registers"]["RDI"], "0x2000")
        self.assertEqual(result["observations"][0]["memory"][0]["data"], "2a")

    def test_unified_breakpoint_can_inspect_and_skip(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("0f05c3")),
            {"breakpoints": [{
                "at": "0x1000",
                "action": "skip",
                "size": 2,
                "capture_registers": ["RAX"],
                "set_registers": {"RAX": "0x99"},
            }]},
            max_steps=20,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["observations"][0]["registers"]["RAX"], "0x0")
        self.assertEqual(result["registers"]["RAX"], "0x99")

    def test_invalid_hook_register_fails_closed(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("c3")),
            {"hooks": [{"addr": "0x1000", "action": "skip", "size": 1, "registers": {"RAXX": 1}}]},
            max_steps=20,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "Invalid replay hooks")

    def test_unmapped_patch_fails_closed(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("31c0c3")),
            {"memory_patches": [{"addr": "0x3000", "data": "01"}]},
            max_steps=20,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "patch_error")

    def test_unmapped_execute_reports_executable_region(self) -> None:
        result = replay_snapshot(_snapshot(bytes.fromhex("e9fb1f0000")), {}, max_steps=20)
        self.assertFalse(result["ok"])
        self.assertEqual(result["fault"]["kind"], "execute")
        self.assertEqual(result["suggested_regions"], [{"addr": "0x3000", "size": 4096, "perm": "rx"}])

    def test_hook_limit_does_not_fall_through_to_original_instruction(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("e800000000e9f6ffffff")),
            {"hooks": [{"addr": "0x1000", "action": "skip", "size": 5, "max_hits": 1}]},
            max_steps=20,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "hook_limit")

    def test_large_trace_returns_without_pipe_timeout(self) -> None:
        result = replay_snapshot(
            _snapshot(bytes.fromhex("ebfe")),
            {},
            max_steps=10_000,
            timeout_sec=5,
            trace_limit=10_000,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stop_reason"], "instruction_limit")
        self.assertEqual(result["steps"], 10_000)



if __name__ == "__main__":
    unittest.main()
