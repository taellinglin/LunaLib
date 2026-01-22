
import os
import sys
import time
from lunalib.mining.miner import Miner

# Minimal config class for Miner
class MinimalConfig:
    def __init__(self):
        self.miner_address = os.environ.get("LUNALIB_MINER_ADDRESS", "LUN_DIAG_TEST")
        self.node_url = os.environ.get("LUNALIB_NODE_URL", "https://bank.linglin.art")
        self.difficulty = int(os.environ.get("LUNALIB_DIAG_DIFFICULTY", "1"))
        self.use_gpu = os.environ.get("LUNALIB_GPU_ENABLED", "1") == "1"
        self.use_cpu = os.environ.get("LUNALIB_CPU_ENABLED", "1") == "1"

# Minimal data manager with required method
class MinimalDataManager:
    def load_mining_history(self):
        return []

def print_status(msg):
    print(f"[DIAG] {msg}")

def main():
    print_status("Starting LunaLib Miner Diagnosis...")

    # Check environment variables
    gpu_env = os.environ.get("LUNALIB_GPU_ENABLED", None)
    cpu_env = os.environ.get("LUNALIB_CPU_ENABLED", None)
    print_status(f"LUNALIB_GPU_ENABLED={gpu_env}")
    print_status(f"LUNALIB_CPU_ENABLED={cpu_env}")

    # Setup config and data manager
    config = MinimalConfig()
    data_manager = MinimalDataManager()
    print_status(f"Miner address: {config.miner_address}")
    print_status(f"Node URL: {config.node_url}")

    miner = Miner(config=config, data_manager=data_manager)
    print_status(f"miner.gpu_enabled={miner.gpu_enabled}")
    print_status(f"miner.cpu_enabled={miner.cpu_enabled}")
    print_status(f"miner.cuda_manager={miner.cuda_manager}")
    print_status(f"cuda_manager.cuda_available={getattr(miner.cuda_manager, 'cuda_available', None)}")

    # Try GPU mining
    if miner.gpu_enabled and miner.cuda_manager and getattr(miner.cuda_manager, 'cuda_available', False):
        print_status("Attempting to start GPU mining...")
        try:
            result = miner._cuda_mine({
                'index': 0,
                'previous_hash': '0'*64,
                'timestamp': time.time(),
                'transactions': [],
                'miner': config.miner_address,
                'difficulty': 1,
                'nonce': 0,
                'reward': 1.0,
                'hash': ''
            }, 1)
            print_status(f"GPU mining result: {result}")
        except Exception as e:
            print_status(f"GPU mining exception: {e}")
    else:
        print_status("GPU mining not available or not enabled.")

    # Try CPU mining
    if miner.cpu_enabled:
        print_status("Attempting to start CPU mining...")
        try:
            result = miner._cpu_mine({
                'index': 0,
                'previous_hash': '0'*64,
                'timestamp': time.time(),
                'transactions': [],
                'miner': config.miner_address,
                'difficulty': 1,
                'nonce': 0,
                'reward': 1.0,
                'hash': ''
            }, 1)
            print_status(f"CPU mining result: {result}")
        except Exception as e:
            print_status(f"CPU mining exception: {e}")
    else:
        print_status("CPU mining not enabled.")

    print_status("Diagnosis complete.")

if __name__ == "__main__":
    main()
