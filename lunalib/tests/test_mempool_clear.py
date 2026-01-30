import pytest
from lunalib.mining.miner import Miner
from lunalib.core.mempool import MempoolManager

class DummyBlockchainManager:
    def get_blockchain_height(self):
        return 0
    def get_latest_block(self):
        return {'hash': '0'*64}
    def submit_mined_block(self, block):
        return True

def test_mempool_cleared_after_mining(monkeypatch):
    # Setup
    mempool = MempoolManager([])
    miner = Miner()
    miner.mempool_manager = mempool
    miner.blockchain_manager = DummyBlockchainManager()
    miner.difficulty_system = type('D', (), {'get_transaction_block_difficulty': lambda self, txs: 1, 'gtx_reward_units': lambda self, x: 0})()
    miner._create_mining_reward_transaction = lambda **kwargs: {'type': 'reward', 'to': 'LUN_test', 'amount': 1, 'timestamp': 0, 'hash': 'a'*64, 'signature': 'ling country', 'public_key': 'ling country', 'version': '2.0'}
    miner._calculate_merkleroot = lambda txs: 'b'*64
    miner._calculate_expected_block_reward = lambda *a, **k: 1
    miner._perform_block_mining = lambda block_data, difficulty: {'success': True, 'hash': 'c'*64, 'nonce': 1}
    miner.mining_stats = {'blocks_mined': 0, 'total_mining_time': 0, 'total_hash_attempts': 0}

    # Add dummy transactions to mempool
    txs = [
        {'type': 'transaction', 'from': 'LUN_a', 'to': 'LUN_b', 'amount': 1, 'timestamp': 0, 'hash': f'{i:064x}', 'signature': 's'*128, 'public_key': 'p'*128}
        for i in range(3)
    ]
    for tx in txs:
        mempool.add_transaction(tx)
    assert mempool.get_mempool_size() == 3

    # Mine a block
    result = miner.mine_block('LUN_test')
    assert result['success']
    # After mining, mempool should be empty (all included txs removed)
    assert mempool.get_mempool_size() == 0
