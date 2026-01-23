import argparse
import os
import struct
import time
import threading
import concurrent.futures
import platform
import ctypes
import multiprocessing as mp

from lunalib.core import sm3 as sm3_mod
from lunalib.core.sm3 import sm3_compact_hash, sm3_digest, sm3_mine_compact


def _parse_cpu_list(value: str | None) -> list[int]:
    if not value:
        return []
    cores: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                continue
            if end < start:
                start, end = end, start
            cores.extend(range(start, end + 1))
        else:
            try:
                cores.append(int(part))
            except ValueError:
                continue
    return [c for c in cores if c >= 0]


def _pin_current_thread(core_id: int) -> bool:
    if core_id < 0:
        return False
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            mask = ctypes.c_size_t(1 << core_id)
            handle = kernel32.GetCurrentThread()
            result = kernel32.SetThreadAffinityMask(handle, mask)
            return bool(result)
        except Exception:
            return False
    if hasattr(os, "sched_setaffinity"):
        try:
            os.sched_setaffinity(0, {core_id})
            return True
        except Exception:
            return False
    return False


def _get_linux_numa_cpulist(node: int) -> list[int]:
    path = f"/sys/devices/system/node/node{node}/cpulist"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return _parse_cpu_list(handle.read().strip())
    except Exception:
        return []


def _get_windows_numa_cpulist(node: int) -> list[int]:
    try:
        kernel32 = ctypes.windll.kernel32
        mask = ctypes.c_ulonglong()
        if not kernel32.GetNumaNodeProcessorMask(ctypes.c_ubyte(node), ctypes.byref(mask)):
            return []
        value = mask.value
        return [i for i in range(64) if (value >> i) & 1]
    except Exception:
        return []


def _get_numa_cpulist(node: int) -> list[int]:
    if os.name == "nt":
        return _get_windows_numa_cpulist(node)
    if os.name == "posix":
        return _get_linux_numa_cpulist(node)
    return []


def build_compact_base80(index: int, previous_hash: str, timestamp: float, miner: str, difficulty: int) -> bytes:
    if len(previous_hash) != 64:
        raise ValueError("previous_hash must be 64 hex chars")
    prev_bytes = bytes.fromhex(previous_hash)
    miner_hash = sm3_digest(str(miner).encode())
    base = (
        prev_bytes
        + int(index).to_bytes(4, "big", signed=False)
        + int(difficulty).to_bytes(4, "big", signed=False)
        + struct.pack(">d", float(timestamp))
        + miner_hash
    )
    if len(base) != 80:
        raise ValueError("compact base80 must be 80 bytes")
    return base


def mine_compact(base80: bytes, difficulty: int, start_nonce: int, max_nonce: int, chunk: int, c_threads: int) -> tuple[int | None, int]:
    if callable(sm3_mine_compact):
        nonce = start_nonce
        attempts = 0
        while nonce < max_nonce:
            count = min(chunk, max_nonce - nonce)
            if c_threads > 1:
                found = sm3_mine_compact(base80, nonce, count, difficulty, c_threads)
            else:
                found = sm3_mine_compact(base80, nonce, count, difficulty)
            attempts += count
            if found is not None:
                return int(found), attempts
            nonce += count
        return None, attempts

    target = "0" * difficulty
    attempts = 0
    for nonce in range(start_nonce, max_nonce):
        attempts += 1
        h = sm3_compact_hash(base80, nonce).hex()
        if h.startswith(target):
            return nonce, attempts
    return None, attempts


def _run_process_bench(
    base80: bytes,
    difficulty: int,
    start_nonce: int,
    max_nonce: int,
    chunk: int,
    workers: int,
    c_threads: int,
    pinning: bool,
    pin_cores: list[int],
    found_event,
    found_value,
    attempts_array,
    proc_index: int,
) -> None:
    found_local = threading.Event()
    attempts = [0 for _ in range(workers)]
    attempts_lock = threading.Lock()

    stride = chunk * workers

    def worker(worker_id: int) -> None:
        if pinning and pin_cores:
            core = pin_cores[worker_id % len(pin_cores)]
            _pin_current_thread(core)
        nonce = start_nonce + (worker_id * chunk)
        while nonce < max_nonce and not found_event.is_set() and not found_local.is_set():
            end_nonce = min(nonce + chunk, max_nonce)
            found, count = mine_compact(base80, difficulty, nonce, end_nonce, chunk, c_threads)
            with attempts_lock:
                attempts[worker_id] += count
                attempts_array[proc_index] = sum(attempts)
            if found is not None:
                if not found_event.is_set():
                    found_value.value = int(found)
                    found_event.set()
                found_local.set()
                return
            nonce += stride

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(worker, wid) for wid in range(workers)]
        concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
        found_local.set()

    with attempts_lock:
        attempts_array[proc_index] = sum(attempts)


def main() -> None:
    parser = argparse.ArgumentParser(description="CPU SM3 compact mining benchmark")
    parser.add_argument("--difficulty", type=int, default=4)
    parser.add_argument("--index", type=int, default=1)
    parser.add_argument("--previous-hash", default="0" * 64)
    parser.add_argument("--miner", default=os.getenv("LUNALIB_MINER_ADDRESS", "bench_miner"))
    parser.add_argument("--max-nonce", type=int, default=5_000_000)
    parser.add_argument("--start-nonce", type=int, default=0)
    parser.add_argument("--chunk", type=int, default=int(os.getenv("LUNALIB_CPU_C_CHUNK", "200000")))
    parser.add_argument("--workers", type=int, default=int(os.getenv("LUNALIB_CPU_WORKERS", str(os.cpu_count() or 1))))
    parser.add_argument("--processes", type=int, default=int(os.getenv("LUNALIB_CPU_PROCESSES", "1")), help="number of processes to spawn")
    parser.add_argument("--status-interval", type=float, default=1.0)
    parser.add_argument("--require-c", action="store_true", help="exit if C extension is unavailable")
    parser.add_argument("--c-threads", type=int, default=1, help="threads per C-extension call")
    parser.add_argument("--pinning", action="store_true", default=bool(int(os.getenv("LUNALIB_CPU_PINNING", "0"))), help="pin worker threads to CPU cores")
    parser.add_argument("--pin-list", default=os.getenv("LUNALIB_CPU_PIN_LIST", ""), help="comma/range list like 0,2-5 for pinning")
    parser.add_argument("--numa", action="store_true", help="limit workers to a NUMA node")
    parser.add_argument("--numa-node", type=int, default=0, help="NUMA node id when --numa is set")
    args = parser.parse_args()

    has_c_ext = bool(getattr(sm3_mod, "_HAS_SM3_EXT", False))
    if args.require_c and not has_c_ext:
        raise SystemExit("C extension not available. Build the extension first.")

    timestamp = time.time()
    base80 = build_compact_base80(args.index, args.previous_hash, timestamp, args.miner, args.difficulty)

    print("CPU bench (compact SM3)")
    print(f"  difficulty: {args.difficulty}")
    print(f"  max_nonce: {args.max_nonce:,}")
    print(f"  chunk: {args.chunk:,}")
    print(f"  workers: {args.workers}")
    print(f"  c_extension: {has_c_ext}")

    start = time.time()
    last = start

    pin_cores = _parse_cpu_list(args.pin_list)
    if args.numa:
        pin_cores = _get_numa_cpulist(args.numa_node) or pin_cores
    if not pin_cores:
        pin_cores = list(range(os.cpu_count() or 1))

    if args.processes <= 1:
        found_event = threading.Event()
        result = {"nonce": None}
        attempts = [0 for _ in range(args.workers)]
        attempts_lock = threading.Lock()

        stride = args.chunk * args.workers

        def worker(worker_id: int) -> None:
            if args.pinning and pin_cores:
                core = pin_cores[worker_id % len(pin_cores)]
                _pin_current_thread(core)
            nonce = args.start_nonce + (worker_id * args.chunk)
            while nonce < args.max_nonce and not found_event.is_set():
                end_nonce = min(nonce + args.chunk, args.max_nonce)
                found, count = mine_compact(base80, args.difficulty, nonce, end_nonce, args.chunk, args.c_threads)
                with attempts_lock:
                    attempts[worker_id] += count
                if found is not None:
                    result["nonce"] = int(found)
                    found_event.set()
                    return
                nonce += stride

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(worker, wid) for wid in range(args.workers)]
            while not found_event.is_set() and any(not f.done() for f in futures):
                now = time.time()
                if now - last >= args.status_interval:
                    with attempts_lock:
                        total_attempts = sum(attempts)
                    elapsed = now - start
                    rate = total_attempts / elapsed if elapsed > 0 else 0.0
                    print(f"  {total_attempts:,} attempts | {rate:,.0f} H/s")
                    last = now
                time.sleep(0.01)

        elapsed_total = time.time() - start
        with attempts_lock:
            total_attempts = sum(attempts)
        rate_total = total_attempts / elapsed_total if elapsed_total > 0 else 0.0

        if result["nonce"] is not None:
            h = sm3_compact_hash(base80, result["nonce"]).hex()
            print(f"✅ Found nonce: {result['nonce']:,}")
            print(f"   hash: {h}")
        else:
            print("⚠️  No nonce found in range")

        print(f"Attempts: {total_attempts:,}")
        print(f"Elapsed: {elapsed_total:.2f}s")
        print(f"Hashrate: {rate_total:,.0f} H/s")
        return

    ctx = mp.get_context("spawn")
    found_event = ctx.Event()
    found_value = ctx.Value("Q", 0)
    attempts_array = ctx.Array("Q", [0] * args.processes)

    total_range = max(0, args.max_nonce - args.start_nonce)
    per = total_range // args.processes
    rem = total_range % args.processes

    processes: list[mp.Process] = []
    offset = args.start_nonce
    for i in range(args.processes):
        span = per + (1 if i < rem else 0)
        if span <= 0:
            break
        proc_start = offset
        proc_end = offset + span
        offset = proc_end
        proc_pin_cores = pin_cores[i::args.processes] if pin_cores else []
        p = ctx.Process(
            target=_run_process_bench,
            args=(
                base80,
                args.difficulty,
                proc_start,
                proc_end,
                args.chunk,
                args.workers,
                args.c_threads,
                args.pinning,
                proc_pin_cores,
                found_event,
                found_value,
                attempts_array,
                i,
            ),
        )
        p.start()
        processes.append(p)

    while any(p.is_alive() for p in processes) and not found_event.is_set():
        now = time.time()
        if now - last >= args.status_interval:
            total_attempts = sum(attempts_array)
            elapsed = now - start
            rate = total_attempts / elapsed if elapsed > 0 else 0.0
            print(f"  {total_attempts:,} attempts | {rate:,.0f} H/s")
            last = now
        time.sleep(0.05)

    found_event.set()
    for p in processes:
        p.join()

    elapsed_total = time.time() - start
    total_attempts = sum(attempts_array)
    rate_total = total_attempts / elapsed_total if elapsed_total > 0 else 0.0

    if found_value.value:
        h = sm3_compact_hash(base80, int(found_value.value)).hex()
        print(f"✅ Found nonce: {int(found_value.value):,}")
        print(f"   hash: {h}")
    else:
        print("⚠️  No nonce found in range")

    print(f"Attempts: {total_attempts:,}")
    print(f"Elapsed: {elapsed_total:.2f}s")
    print(f"Hashrate: {rate_total:,.0f} H/s")


if __name__ == "__main__":
    main()