from __future__ import annotations

import functools
import os
import queue
import threading
import time

import idaapi
import idc

_MAIN_THREAD_ID = threading.get_ident()
_CALL_QUEUE: queue.Queue[tuple[callable, queue.Queue[tuple[str, object]]]] = queue.Queue()


def _run_with_batch(func):
    old_batch = idc.batch(1)
    try:
        return func()
    finally:
        idc.batch(old_batch)


def pump_main_thread(timeout_sec: float = 0.1, max_items: int = 32) -> int:
    processed = 0
    deadline = time.monotonic() + max(0.0, timeout_sec)
    while processed < max_items:
        remaining = max(0.0, deadline - time.monotonic())
        wait_timeout = 0.0 if processed else remaining
        try:
            func, result_queue = _CALL_QUEUE.get(timeout=wait_timeout)
        except queue.Empty:
            break
        try:
            result_queue.put(("ok", _run_with_batch(func)))
        except Exception as exc:
            result_queue.put(("err", exc))
        processed += 1
    return processed


def run_in_ida(func):
    sync_mode = (os.getenv("IDEA_IDA_SYNC_MODE", "").strip() or "execute_sync").lower()
    if sync_mode == "direct":
        return _run_with_batch(func)
    if sync_mode == "queue":
        if threading.get_ident() == _MAIN_THREAD_ID:
            return _run_with_batch(func)
        result_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        _CALL_QUEUE.put((func, result_queue))
        status, value = result_queue.get()
        if status == "err":
            raise value  # type: ignore[misc]
        return value

    result_queue: queue.Queue[tuple[str, object]] = queue.Queue()

    def runner():
        try:
            result_queue.put(("ok", _run_with_batch(func)))
        except Exception as exc:
            result_queue.put(("err", exc))
        return 1

    idaapi.execute_sync(runner, idaapi.MFF_WRITE)
    status, value = result_queue.get()
    if status == "err":
        raise value  # type: ignore[misc]
    return value


def idasync(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return run_in_ida(lambda: func(*args, **kwargs))

    return wrapper
