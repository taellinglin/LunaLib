import argparse
import json
import threading
import time
import hashlib
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

import requests

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from lunalib.core.blockchain import BlockchainManager
from lunalib.core.daemon import BlockchainDaemon
from lunalib.core.mempool import MempoolManager
from lunalib.gtx.digital_bill import DigitalBill
from lunalib.mining.difficulty import DifficultySystem
from lunalib.transactions.transactions import TransactionManager
from lunalib.core.crypto import KeyManager


class InMemoryChain:
    def __init__(self):
        self.blocks = []

    def get_latest_block(self):
        return self.blocks[-1] if self.blocks else None

    def submit_mined_block(self, block):
        self.blocks.append(block)
        return True


def _hash_block(payload: dict, difficulty: int) -> tuple[str, int]:
    nonce = 0
    target = "0" * max(1, difficulty)
    while True:
        blob = json.dumps({**payload, "nonce": nonce}, sort_keys=True).encode()
        digest = hashlib.sha256(blob).hexdigest()
        if digest.startswith(target):
            return digest, nonce
        nonce += 1


def _make_mock_bill_tx(denomination: float, user_address: str) -> dict:
    bill = DigitalBill(
        denomination=denomination,
        user_address=user_address,
        difficulty=1,
        bill_data={"bench": True},
    )
    mined_hash = hashlib.sha256(f"bench|{time.time()}".encode()).hexdigest()
    info = bill.finalize(hash=mined_hash, nonce=1, mining_time=0.01)
    return info.get("transaction_data", {})


def build_chain(blocks: int, tx_per_block: int, difficulty: int, miner: str) -> list[dict]:
    difficulty_system = DifficultySystem()
    chain = []

    genesis = {
        "index": 0,
        "previous_hash": "0" * 64,
        "timestamp": time.time(),
        "transactions": [
            {
                "type": "reward",
                "to": miner,
                "amount": difficulty_system.calculate_block_reward(difficulty),
                "timestamp": time.time(),
                "hash": "genesis_reward",
            }
        ],
        "miner": miner,
        "difficulty": difficulty,
        "reward": difficulty_system.calculate_block_reward(difficulty),
    }
    genesis_hash, genesis_nonce = _hash_block(genesis, difficulty)
    genesis["hash"] = genesis_hash
    genesis["nonce"] = genesis_nonce
    chain.append(genesis)

    for idx in range(1, blocks):
        previous_hash = chain[-1]["hash"]
        txs = []
        for i in range(tx_per_block):
            if i % 3 == 0:
                txs.append(_make_mock_bill_tx(denomination=1.0 + i, user_address=miner))
            else:
                txs.append(
                    {
                        "type": "transaction",
                        "from": f"LUN_sender_{i}",
                        "to": miner,
                        "amount": 0.5,
                        "fee": 0.001,
                        "timestamp": time.time(),
                        "hash": f"tx_{idx}_{i}",
                    }
                )

        block = {
            "index": idx,
            "previous_hash": previous_hash,
            "timestamp": time.time(),
            "transactions": txs,
            "miner": miner,
            "difficulty": difficulty,
            "reward": difficulty_system.calculate_block_reward(difficulty),
        }
        block_hash, nonce = _hash_block(block, difficulty)
        block["hash"] = block_hash
        block["nonce"] = nonce
        chain.append(block)

    return chain


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class BenchHandler(BaseHTTPRequestHandler):
    chain_ref = None
    mempool_ref = None
    daemon_ref = None

    def _json(self, status: int, payload: dict | list):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def log_message(self, format, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/system/health", "/health"):
            return self._json(200, {"status": "ok"})

        if parsed.path in ("/blockchain", "/api/blockchain/full", "/blockchain/blocks"):
            return self._json(200, {"blocks": self.chain_ref})

        if parsed.path == "/api/blockchain/latest":
            latest = self.chain_ref[-1] if self.chain_ref else None
            return self._json(200, latest or {})

        if parsed.path.startswith("/blockchain/block/"):
            try:
                height = int(parsed.path.split("/")[-1])
                block = self.chain_ref[height]
                return self._json(200, block)
            except Exception:
                return self._json(404, {"error": "block not found"})

        if parsed.path == "/blockchain/range":
            qs = parse_qs(parsed.query)
            start = int(qs.get("start", [0])[0])
            end = int(qs.get("end", [0])[0])
            blocks = self.chain_ref[start : end + 1]
            return self._json(200, {"blocks": blocks})

        if parsed.path == "/mempool":
            return self._json(200, list(self.mempool_ref))

        if parsed.path == "/api/peers/list":
            return self._json(200, {"peers": []})

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path in ("/mempool/add", "/api/mempool/add"):
            tx = self._read_json()
            validation = self.daemon_ref.validate_transaction(tx)
            if validation.get("valid"):
                self.mempool_ref.append(tx)
                return self._json(200, {"success": True, "transaction_hash": tx.get("hash")})
            return self._json(400, {"success": False, "error": validation.get("message")})

        if parsed.path in ("/mempool/add/batch", "/api/mempool/add/batch"):
            payload = self._read_json()
            txs = payload.get("transactions", []) if isinstance(payload, dict) else payload
            accepted = 0
            for tx in txs:
                validation = self.daemon_ref.validate_transaction(tx)
                if validation.get("valid"):
                    self.mempool_ref.append(tx)
                    accepted += 1
            return self._json(200, {"success": True, "accepted": accepted, "total": len(txs)})

        if parsed.path == "/api/blocks/validate":
            block = self._read_json()
            return self._json(200, self.daemon_ref.validate_block(block))

        if parsed.path == "/api/transactions/validate":
            tx = self._read_json()
            return self._json(200, self.daemon_ref.validate_transaction(tx))

        if parsed.path == "/api/peers/register":
            peer = self._read_json()
            return self._json(200, {"success": True, "peer": peer})

        if parsed.path == "/blockchain/submit-block":
            block = self._read_json()
            self.chain_ref.append(block)
            return self._json(200, {"success": True, "block_hash": block.get("hash")})

        return self._json(404, {"error": "not found"})


def run_server(chain, mempool, daemon, host, port):
    BenchHandler.chain_ref = chain
    BenchHandler.mempool_ref = mempool
    BenchHandler.daemon_ref = daemon
    server = ThreadedHTTPServer((host, port), BenchHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    parser = argparse.ArgumentParser(description="LunaLib full ecosystem benchmark")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--blocks", type=int, default=30)
    parser.add_argument("--tx-per-block", type=int, default=8)
    parser.add_argument("--difficulty", type=int, default=1)
    parser.add_argument("--miner", default="LUN_bench_miner")
    parser.add_argument("--stress-iterations", type=int, default=50)
    parser.add_argument("--stress-broadcast", type=int, default=50)
    parser.add_argument("--mine-blocks", type=int, default=3)
    parser.add_argument("--mempool-burst", type=int, default=100)
    parser.add_argument("--sign-workers", type=int, default=8)
    parser.add_argument("--no-parallel-sign", action="store_true")
    args = parser.parse_args()

    stats = {
        "chain_build_seconds": 0.0,
        "scan_chain_seconds": 0.0,
        "get_blocks_range_seconds": 0.0,
        "broadcast_single_seconds": 0.0,
        "tx_sign_batch_seconds": 0.0,
        "stress_scan_seconds": 0.0,
        "stress_range_seconds": 0.0,
        "stress_broadcast_seconds": 0.0,
        "stress_broadcast_success": 0,
        "mempool_burst_seconds": 0.0,
        "mempool_burst_success": 0,
        "mined_blocks": 0,
        "mining_seconds": 0.0,
    }

    print("[BENCH] Building in-memory chain...")
    start = time.perf_counter()
    chain = build_chain(args.blocks, args.tx_per_block, args.difficulty, args.miner)
    build_elapsed = time.perf_counter() - start
    stats["chain_build_seconds"] = build_elapsed
    print(f"[BENCH] Chain build: {args.blocks} blocks in {build_elapsed:.4f}s")

    mempool = []
    in_memory = InMemoryChain()
    in_memory.blocks = chain

    mempool_manager = MempoolManager(network_endpoints=[])
    daemon = BlockchainDaemon(in_memory, mempool_manager)

    server = run_server(chain, mempool, daemon, args.host, args.port)
    base_url = f"http://{args.host}:{args.port}"
    print(f"[BENCH] Server running at {base_url}")

    manager = BlockchainManager(endpoint_url=base_url)

    print("[BENCH] scan_chain...")
    start = time.perf_counter()
    if hasattr(manager, "scan_chain"):
        data = manager.scan_chain()
    else:
        response = requests.get(f"{base_url}/blockchain", timeout=30)
        data = response.json()
    scan_elapsed = time.perf_counter() - start
    stats["scan_chain_seconds"] = scan_elapsed
    print(f"[BENCH] scan_chain: {len(data.get('blocks', []))} blocks in {scan_elapsed:.4f}s")

    print("[BENCH] reward scan...")
    start = time.perf_counter()
    reward_txs = manager.scan_transactions_for_address(args.miner)
    reward_elapsed = time.perf_counter() - start
    reward_count = sum(1 for tx in reward_txs if str(tx.get("type", "")).lower() == "reward" or str(tx.get("from", "")).lower() == "network")
    print(f"[BENCH] reward scan: {reward_count} reward txs for {args.miner} in {reward_elapsed:.4f}s")

    print("[BENCH] get_blocks_range...")
    start = time.perf_counter()
    blocks = manager.get_blocks_range(0, min(10, args.blocks - 1))
    range_elapsed = time.perf_counter() - start
    stats["get_blocks_range_seconds"] = range_elapsed
    print(f"[BENCH] get_blocks_range: {len(blocks)} blocks in {range_elapsed:.4f}s")

    tm = TransactionManager(network_endpoints=[base_url])
    key_manager = KeyManager()
    priv_key, pub_key, from_addr = key_manager.generate_keypair()
    tx = tm.create_transaction(from_addr, args.miner, 1.0, private_key=priv_key, public_key=pub_key, memo="bench")

    print("[BENCH] broadcast_transaction...")
    start = time.perf_counter()
    ok, msg = manager.broadcast_transaction(tx)
    broadcast_elapsed = time.perf_counter() - start
    stats["broadcast_single_seconds"] = broadcast_elapsed
    print(f"[BENCH] broadcast_transaction: {ok} in {broadcast_elapsed:.4f}s ({msg})")

    print("[BENCH] mempool size:", len(mempool))

    print("[STRESS] scan_chain repeated...")
    start = time.perf_counter()
    for _ in range(args.stress_iterations):
        if hasattr(manager, "scan_chain"):
            manager.scan_chain()
        else:
            requests.get(f"{base_url}/blockchain", timeout=30)
    elapsed = time.perf_counter() - start
    stats["stress_scan_seconds"] = elapsed
    print(f"[STRESS] scan_chain x{args.stress_iterations}: {elapsed:.4f}s")

    print("[STRESS] get_blocks_range repeated...")
    start = time.perf_counter()
    for _ in range(args.stress_iterations):
        manager.get_blocks_range(0, min(10, args.blocks - 1))
    elapsed = time.perf_counter() - start
    stats["stress_range_seconds"] = elapsed
    print(f"[STRESS] get_blocks_range x{args.stress_iterations}: {elapsed:.4f}s")

    print("[STRESS] broadcast transactions (batched + parallel)...")
    success_count = 0
    batch_size = 25
    batch_amounts = [1.0] * args.stress_broadcast

    sign_start = time.perf_counter()
    batches = tm.create_transactions_batch(
        from_addr,
        args.miner,
        batch_amounts,
        private_key=priv_key,
        public_key=pub_key,
        memo_prefix="bench-",
        parallel_sign=not args.no_parallel_sign,
        sign_workers=args.sign_workers,
    )
    stats["tx_sign_batch_seconds"] = time.perf_counter() - sign_start

    start = time.perf_counter()
    batch_payloads = [
        {"transactions": batches[i : i + batch_size]}
        for i in range(0, len(batches), batch_size)
    ]

    def _post_batch(payload):
        resp = requests.post(f"{base_url}/mempool/add/batch", json=payload, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("accepted", 0)
        return 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        for accepted in pool.map(_post_batch, batch_payloads):
            success_count += accepted

    elapsed = time.perf_counter() - start
    stats["stress_broadcast_seconds"] = elapsed
    stats["stress_broadcast_success"] = success_count
    print(
        f"[STRESS] broadcast x{args.stress_broadcast}: {elapsed:.4f}s "
        f"(accepted={success_count})"
    )

    print("[STRESS] mempool burst (batched + parallel)...")
    start = time.perf_counter()
    burst_success = 0
    burst = []
    burst_amounts = [0.1] * args.mempool_burst
    burst.extend(
        tm.create_transactions_batch(
            from_addr,
            args.miner,
            burst_amounts,
            private_key=priv_key,
            public_key=pub_key,
            memo_prefix="burst-",
            parallel_sign=not args.no_parallel_sign,
            sign_workers=args.sign_workers,
        )
    )
    burst_payloads = [
        {"transactions": burst[i : i + batch_size]}
        for i in range(0, len(burst), batch_size)
    ]
    with ThreadPoolExecutor(max_workers=8) as pool:
        for accepted in pool.map(_post_batch, burst_payloads):
            burst_success += accepted
    elapsed = time.perf_counter() - start
    stats["mempool_burst_seconds"] = elapsed
    stats["mempool_burst_success"] = burst_success
    print(f"[STRESS] mempool burst x{args.mempool_burst}: {elapsed:.4f}s (accepted={burst_success})")

    print("[BENCH] mining blocks...")
    start = time.perf_counter()
    mined = 0
    for _ in range(args.mine_blocks):
        previous_hash = chain[-1]["hash"] if chain else "0" * 64
        index = len(chain)
        block = {
            "index": index,
            "previous_hash": previous_hash,
            "timestamp": time.time(),
            "transactions": [
                _make_mock_bill_tx(denomination=1.0, user_address=args.miner)
            ],
            "miner": args.miner,
            "difficulty": args.difficulty,
            "reward": DifficultySystem().calculate_block_reward(args.difficulty),
        }
        block_hash, nonce = _hash_block(block, args.difficulty)
        block["hash"] = block_hash
        block["nonce"] = nonce
        chain.append(block)
        mined += 1
    mining_elapsed = time.perf_counter() - start
    stats["mined_blocks"] = mined
    stats["mining_seconds"] = mining_elapsed
    print(f"[BENCH] mined {mined} blocks in {mining_elapsed:.4f}s")

    print("[SUMMARY] ========================")
    print(f"Chain build: {stats['chain_build_seconds']:.4f}s")
    print(f"scan_chain: {stats['scan_chain_seconds']:.4f}s")
    print(f"get_blocks_range: {stats['get_blocks_range_seconds']:.4f}s")
    print(f"broadcast_single: {stats['broadcast_single_seconds']:.4f}s")
    print(f"sign_batch: {stats['tx_sign_batch_seconds']:.4f}s")
    if args.stress_broadcast:
        print(
            f"sign_batch avg: {stats['tx_sign_batch_seconds'] / args.stress_broadcast:.6f}s/tx "
            f"| {args.stress_broadcast / max(stats['tx_sign_batch_seconds'], 1e-9):.2f} tx/s"
        )
    print(f"stress scan x{args.stress_iterations}: {stats['stress_scan_seconds']:.4f}s")
    print(f"stress range x{args.stress_iterations}: {stats['stress_range_seconds']:.4f}s")
    if args.stress_iterations:
        print(
            f"scan avg: {stats['stress_scan_seconds'] / args.stress_iterations:.6f}s/iter"
        )
        print(
            f"range avg: {stats['stress_range_seconds'] / args.stress_iterations:.6f}s/iter"
        )
    print(
        f"stress broadcast x{args.stress_broadcast}: {stats['stress_broadcast_seconds']:.4f}s "
        f"(success={stats['stress_broadcast_success']})"
    )
    if args.stress_broadcast:
        print(
            f"stress broadcast avg: {stats['stress_broadcast_seconds'] / args.stress_broadcast:.6f}s/tx "
            f"| {args.stress_broadcast / max(stats['stress_broadcast_seconds'], 1e-9):.2f} tx/s"
        )
    print(
        f"mempool burst x{args.mempool_burst}: {stats['mempool_burst_seconds']:.4f}s "
        f"(success={stats['mempool_burst_success']})"
    )
    if args.mempool_burst:
        print(
            f"mempool burst avg: {stats['mempool_burst_seconds'] / args.mempool_burst:.6f}s/tx "
            f"| {args.mempool_burst / max(stats['mempool_burst_seconds'], 1e-9):.2f} tx/s"
        )
    print(f"mined blocks: {stats['mined_blocks']} in {stats['mining_seconds']:.4f}s")
    if stats['mined_blocks']:
        print(
            f"mining avg: {stats['mining_seconds'] / stats['mined_blocks']:.6f}s/block "
            f"| {stats['mined_blocks'] / max(stats['mining_seconds'], 1e-9):.2f} blocks/s"
        )
    print(f"mempool size: {len(mempool)}")
    print(f"chain height: {len(chain) - 1}")
    mempool_stats = mempool_manager.get_stats() if hasattr(mempool_manager, "get_stats") else {}
    daemon_stats = daemon.get_stats() if hasattr(daemon, "get_stats") else {}
    if mempool_stats:
        print(
            "[SUMMARY] mempool broadcast avg (single): "
            f"{(mempool_stats['broadcast_seconds'] / max(1, mempool_stats['broadcast_count'])):.6f}s"
        )
        print(
            "[SUMMARY] mempool broadcast avg (batch): "
            f"{(mempool_stats['batch_broadcast_seconds'] / max(1, mempool_stats['batch_broadcast_count'])):.6f}s"
        )
    if daemon_stats:
        print(
            "[SUMMARY] tx validation avg: "
            f"{(daemon_stats['tx_validation_seconds'] / max(1, daemon_stats['tx_validation_count'])):.6f}s"
        )
    print("[SUMMARY] ========================")

    print("[BENCH] shutting down server")
    server.shutdown()


if __name__ == "__main__":
    main()
