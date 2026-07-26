import unittest
from unittest.mock import AsyncMock, patch

from ida_hybrid_manager import backend


class BackendTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_timeout_is_not_unavailable(self) -> None:
        with patch.object(backend.asyncio, "to_thread", AsyncMock(side_effect=TimeoutError)):
            with self.assertRaises(backend.BackendTimeoutError):
                await backend.call_backend_tool(
                    {"transport": "native-http", "url": "http://127.0.0.1:1"},
                    "search",
                    {},
                    timeout_sec=3,
                )

    async def test_timeout_does_not_retry_endpoint_alias(self) -> None:
        with patch.object(
            backend,
            "call_backend_tool",
            AsyncMock(side_effect=backend.BackendTimeoutError("late")),
        ) as call:
            with self.assertRaises(backend.BackendTimeoutError):
                await backend.call_backend_tool_any(
                    [
                        {"transport": "native-http", "url": "http://host-a:1"},
                        {"transport": "native-http", "url": "http://host-b:1"},
                    ],
                    "search",
                    {},
                )
        self.assertEqual(call.await_count, 1)


if __name__ == "__main__":
    unittest.main()
