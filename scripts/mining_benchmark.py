import os
import time
from lunalib.mining.miner import Miner

# Minimal config and data manager for testing
class MinimalConfig:
    def __init__(self, miner_address, node_url, difficulty=1):
        self.miner_address = miner_address
        self.node_url = node_url
        self.difficulty = difficulty
        self.use_gpu = True
        self.use_cpu = True

class MinimalDataManager:
    def load_mining_history(self):
        return []

def run_batch_mining_tests(miner, num_batches=5, batch_size=10000, difficulty=1):
    print("[BATCH TEST] Starting batch mining test...")
    results = []
    for i in range(num_batches):
        print(f"[BATCH TEST] Batch {i+1}/{num_batches} (batch_size={batch_size}, difficulty={difficulty})")
        block_data = {
            'index': i,
            'previous_hash': '0'*64,
            'timestamp': time.time(),
            'transactions': [],
            'miner': miner.config.miner_address,
            'difficulty': difficulty,
            'nonce': 0,
            'reward': 1.0,
            'hash': ''
        }
        start = time.perf_counter()
        if miner.gpu_enabled and miner.cuda_manager and miner.cuda_manager.cuda_available:
            result = miner._cuda_mine(block_data, difficulty)
            method = 'GPU'
        else:
            result = miner._cpu_mine(block_data, difficulty)
            method = 'CPU'
        elapsed = time.perf_counter() - start
        print(f"[BATCH TEST] {method} mining result: {result}")
        print(f"[BATCH TEST] Time elapsed: {elapsed:.4f}s")
        results.append({'method': method, 'result': result, 'elapsed': elapsed})
    print("[BATCH TEST] Batch mining test complete.")
    return results

def mining_benchmark(miner, num_blocks=10, difficulty=1):
    print("[BENCHMARK] Starting mining benchmark with multiple configurations...")
    configs = []
    # Test different CPU worker counts
    for cpu_workers in [1, 2, 4, 8, 16]:
        miner.set_cpu_workers(cpu_workers)
        # Test different difficulties
        for diff in [1, 2, 3]:
            # Test different GPU batch sizes (if available)
            for batch_size in [1000, 10000, 100000]:
                if miner.gpu_enabled and miner.cuda_manager and miner.cuda_manager.cuda_available:
                    os.environ['LUNALIB_CUDA_BATCH_SIZE'] = str(batch_size)
                times = []
                for i in range(3):
                    block_data = {
                        'index': i,
                        'previous_hash': '0'*64,
                        'timestamp': time.time(),
                        'transactions': [],
                        'miner': miner.config.miner_address,
                        'difficulty': diff,
                        'nonce': 0,
                        'reward': 1.0,
                        'hash': ''
                    }
                    start = time.perf_counter()
                    if miner.gpu_enabled and miner.cuda_manager and miner.cuda_manager.cuda_available:
                        result = miner._cuda_mine(block_data, diff)
                        method = f'GPU (batch={batch_size})'
                    else:
                        result = miner._cpu_mine(block_data, diff)
                        method = f'CPU ({cpu_workers} threads)'
                    elapsed = time.perf_counter() - start
                    print(f"[BENCHMARK] Block {i+1}/3 | {method} | Difficulty: {diff} | Time: {elapsed:.4f}s | Result: {result}")
                    times.append(elapsed)
                avg_time = sum(times) / len(times) if times else 0
                configs.append({
                    'method': method,
                    'cpu_workers': cpu_workers,
                    'batch_size': batch_size if 'GPU' in method else None,
                    'difficulty': diff,
                    'avg_time': avg_time,
                    'blocks_per_sec': 1/avg_time if avg_time > 0 else 0
                })
    # Find optimal config
    best = min(configs, key=lambda c: c['avg_time'])
    print("\n[RESULTS] =====================")
    for c in configs:
        print(f"{c['method']} | Difficulty: {c['difficulty']} | Avg Time: {c['avg_time']:.4f}s | Blocks/sec: {c['blocks_per_sec']:.2f}")
    print("[RESULTS] =====================")
    print(f"[OPTIMAL] {best['method']} | Difficulty: {best['difficulty']} | Avg Time: {best['avg_time']:.4f}s | Blocks/sec: {best['blocks_per_sec']:.2f}")
    print("[BENCHMARK] Mining benchmark complete.")
    return configs

def main():
    miner_address = os.environ.get("LUNALIB_MINER_ADDRESS", "LUN_BENCH_TEST")
    node_url = os.environ.get("LUNALIB_NODE_URL", "https://bank.linglin.art")
    difficulty = int(os.environ.get("LUNALIB_BENCH_DIFFICULTY", "1"))
    config = MinimalConfig(miner_address, node_url, difficulty)
    data_manager = MinimalDataManager()
    miner = Miner(config=config, data_manager=data_manager)
    miner.hashrate_callback = None

    # Batch mining test
    run_batch_mining_tests(miner, num_batches=3, batch_size=10000, difficulty=difficulty)

    # Mining benchmark
    mining_benchmark(miner, num_blocks=5, difficulty=difficulty)

if __name__ == "__main__":
    main()
