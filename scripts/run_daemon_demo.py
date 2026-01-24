import time
import os
import sys
from typing import Dict, List

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from lunalib.core.daemon import BlockchainDaemon
from lunalib.core.daemon_server import DaemonHTTPServer
from lunalib.core.mempool import MempoolManager
from lunalib.core.blockchain import BlockchainManager
from lunalib.core.crypto import KeyManager
from lunalib.mining.miner import Miner
from lunalib.mining.difficulty import DifficultySystem
from lunalib.transactions.transactions import TransactionManager


class InMemoryChain:
    def __init__(self):
        self.blocks: List[Dict] = []

    def get_latest_block(self):
        return self.blocks[-1] if self.blocks else None

    def submit_mined_block(self, block):
        self.blocks.append(block)
        return True


class SimpleDataManager:
    def load_mining_history(self):
        return []

    def save_mining_history(self, _history):
        return True

    def load_mined_blocks(self):
        return []

    def load_mined_bills(self):
        return []

    def save_mined_bills(self, _bills):
        return True

    def save_mined_rewards(self, _rewards):
        return True

    def record_mined_block(self, _block):
        return True

    def update_mining_stats(self, _stats):
        return True

    def update_bills_db(self, _block):
        return True


class SimpleConfig:
    def __init__(self, node_url: str, miner_address: str, difficulty: int = 1):
        self.node_url = node_url
        self.miner_address = miner_address
        self.difficulty = difficulty
        self.load_balance_mode = "parallel"
        self.enable_cpu_mining = True
        self.enable_gpu_mining = True


def create_genesis(chain: InMemoryChain, miner_address: str, difficulty: int) -> None:
    tm = TransactionManager(network_endpoints=[])
    difficulty_system = DifficultySystem()
    try:
        reward_amount = difficulty_system.calculate_block_reward(
            difficulty,
            block_height=0,
            tx_count=0,
            fees_total=0.0,
            base_reward=float(difficulty),
        )
    except TypeError:
        reward_amount = difficulty_system.calculate_block_reward(difficulty)
    reward_tx = tm.create_reward_transaction(miner_address, amount=reward_amount, block_height=0)

    block = {
        "index": 0,
        "previous_hash": "0" * 64,
        "timestamp": time.time(),
        "transactions": [reward_tx],
        "miner": miner_address,
        "difficulty": difficulty,
        "nonce": 0,
        "reward": reward_tx["amount"],
        "hash": "0" * 64,
    }
    chain.blocks.append(block)


def main() -> None:
    host = "127.0.0.1"
    port = 8765
    base_url = f"http://{host}:{port}"

    os.environ["LUNALIB_CUDA_SM3"] = "1"
    os.environ["LUNALIB_MINING_HASH_MODE"] = "compact"
    os.environ["LUNALIB_CUDA_CHUNK_SIZE"] = "200000"
    os.environ["LUNALIB_BLOCK_REWARD_BASE_MULT"] = "0.0001"

    chain = InMemoryChain()
    mempool = MempoolManager(network_endpoints=[])
    if hasattr(mempool, "clear_mempool"):
        mempool.clear_mempool()
    daemon = BlockchainDaemon(chain, mempool)
    server = DaemonHTTPServer(daemon, chain, mempool, host=host, port=port)
    server.start()
    print(f"✅ Daemon HTTP server running at {base_url}")

    key_manager = KeyManager()
    miner_priv, miner_pub, miner_addr = key_manager.generate_keypair()
    recipient_priv, recipient_pub, recipient_addr = key_manager.generate_keypair()

    difficulty = 2
    create_genesis(chain, miner_addr, difficulty)
    print(f"🌱 Genesis block created for miner {miner_addr}")

    config = SimpleConfig(node_url=base_url, miner_address=miner_addr, difficulty=difficulty)
    miner = Miner(config=config, data_manager=SimpleDataManager())
    if miner.cuda_manager:
        miner.cuda_manager.use_sm3_kernel = True

    tx_manager = TransactionManager(network_endpoints=[])
    pre_tx = tx_manager.create_transfer(
        from_address=miner_addr,
        to_address=recipient_addr,
        amount=0.5,
        private_key=miner_priv,
        memo="demo pre-mine transfer",
    )
    mempool.add_transaction(pre_tx)

    print("⛏️  Mining first block for reward...")
    ok, msg, block = miner.mine_block()
    print(f"Miner result: {ok} | {msg}")

    manager = BlockchainManager(endpoint_url=base_url)
    rewards = manager.scan_transactions_for_address(miner_addr)
    reward_total = sum(float(tx.get("amount", 0)) for tx in rewards if str(tx.get("type", "")).lower() == "reward")
    print(f"💰 Rewards found for miner: {reward_total}")

    tx_manager = TransactionManager(network_endpoints=[base_url])
    transfer = tx_manager.create_transfer(
        from_address=miner_addr,
        to_address=recipient_addr,
        amount=0.5,
        private_key=miner_priv,
        memo="demo transfer",
    )

    ok, msg = tx_manager.send_transaction(transfer)
    print(f"📤 Sent transfer to mempool: {ok} | {msg}")

    print("⛏️  Mining second block to include transfer...")
    ok, msg, block = miner.mine_block()
    print(f"Miner result: {ok} | {msg}")

    recipient_txs = manager.scan_transactions_for_address(recipient_addr)
    print(f"📥 Recipient transactions: {len(recipient_txs)}")

    print("✅ Demo complete. Press Ctrl+C to stop the server.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
