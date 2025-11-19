from lunalib.storage.cache import BlockchainCache
import requests
import time
import json
from typing import Dict, List, Optional, Tuple


class BlockchainManager:
    """Manages blockchain interactions and scanning"""
    
    def __init__(self, endpoint_url="https://bank.linglin.art"):
        self.endpoint_url = endpoint_url.rstrip('/')
        self.cache = BlockchainCache()
        self.network_connected = False
        
    def get_blockchain_height(self) -> int:
        """Get current blockchain height - FIXED VERSION"""
        try:
            # Method 1: Try the blocks endpoint (most reliable)
            response = requests.get(f'{self.endpoint_url}/blockchain/blocks', timeout=10)
            if response.status_code == 200:
                data = response.json()
                blocks = data.get('blocks', [])
                
                # Calculate height correctly
                if blocks:
                    # Height should be the index of the latest block
                    latest_block_index = blocks[-1].get('index', len(blocks) - 1)
                    print(f"📊 Blocks count: {len(blocks)}, Latest block index: {latest_block_index}")
                    return latest_block_index
                else:
                    return 0  # No blocks yet
                    
            # If blocks endpoint fails, try height endpoint as fallback
            response = requests.get(f'{self.endpoint_url}/blockchain/height', timeout=10)
            if response.status_code == 200:
                data = response.json()
                height = data.get('height', 0)
                print(f"📊 Height endpoint returned: {height}")
                return height
                
        except Exception as e:
            print(f"Blockchain height error: {e}")
            
        print("⚠️  Using fallback height: 0")
        return 0
    
    def get_block(self, height: int) -> Optional[Dict]:
        """Get block by height"""
        # Check cache first
        cached_block = self.cache.get_block(height)
        if cached_block:
            return cached_block
            
        try:
            response = requests.get(f'{self.endpoint_url}/blockchain/block/{height}', timeout=10)
            if response.status_code == 200:
                block = response.json()
                self.cache.save_block(height, block.get('hash', ''), block)
                return block
        except Exception as e:
            print(f"Get block error: {e}")
            
        return None
    
    def get_blocks_range(self, start_height: int, end_height: int) -> List[Dict]:
        """Get range of blocks"""
        blocks = []
        
        # Check cache first
        cached_blocks = self.cache.get_block_range(start_height, end_height)
        if len(cached_blocks) == (end_height - start_height + 1):
            return cached_blocks
            
        try:
            response = requests.get(
                f'{self.endpoint_url}/blockchain/range?start={start_height}&end={end_height}',
                timeout=30
            )
            if response.status_code == 200:
                blocks = response.json().get('blocks', [])
                # Cache the blocks
                for block in blocks:
                    height = block.get('index', 0)
                    self.cache.save_block(height, block.get('hash', ''), block)
            else:
                # Fallback: get blocks individually
                for height in range(start_height, end_height + 1):
                    block = self.get_block(height)
                    if block:
                        blocks.append(block)
                    time.sleep(0.01)  # Be nice to the API
                        
        except Exception as e:
            print(f"Get blocks range error: {e}")
            
        return blocks
    
    def get_mempool(self) -> List[Dict]:
        """Get current mempool transactions"""
        try:
            response = requests.get(f'{self.endpoint_url}/mempool', timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Mempool error: {e}")
            
        return []
    
    def broadcast_transaction(self, transaction: Dict) -> bool:
        """Broadcast transaction to network"""
        try:
            response = requests.post(
                f'{self.endpoint_url}/mempool/add',
                json=transaction,
                timeout=30
            )
            return response.status_code == 201
        except Exception as e:
            print(f"Broadcast error: {e}")
            return False
    
    def check_network_connection(self) -> bool:
        """Check if network is accessible"""
        try:
            response = requests.get(f'{self.endpoint_url}/health', timeout=5)
            self.network_connected = response.status_code == 200
            return self.network_connected
        except:
            self.network_connected = False
            return False
    
    def scan_transactions_for_address(self, address: str, start_height: int = 0, end_height: int = None) -> List[Dict]:
        """Scan blockchain for transactions involving an address"""
        if end_height is None:
            end_height = self.get_blockchain_height()
            
        transactions = []
        
        # Scan in batches for efficiency
        batch_size = 100
        for batch_start in range(start_height, end_height + 1, batch_size):
            batch_end = min(batch_start + batch_size - 1, end_height)
            blocks = self.get_blocks_range(batch_start, batch_end)
            
            for block in blocks:
                block_transactions = self._find_address_transactions(block, address)
                transactions.extend(block_transactions)
                
        return transactions
    def submit_mined_block(self, block_data: Dict) -> bool:
        """Submit a mined block to the network with built-in validation"""
        try:
            print(f"🔄 Preparing to submit block #{block_data.get('index')}...")
            
            # Step 1: Validate block structure before submission
            validation_result = self._validate_block_structure(block_data)
            if not validation_result['valid']:
                print(f"❌ Block validation failed:")
                for issue in validation_result['issues']:
                    print(f"   - {issue}")
                return False
            
            print(f"✅ Block structure validation passed")
            print(f"   Block #{block_data.get('index')} | Hash: {block_data.get('hash', '')[:16]}...")
            print(f"   Transactions: {len(block_data.get('transactions', []))} | Difficulty: {block_data.get('difficulty')}")
            
            # Step 2: Submit to the correct endpoint
            response = requests.post(
                f'{self.endpoint_url}/blockchain/submit-block',
                json=block_data,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            # Step 3: Handle response
            if response.status_code in [200, 201]:
                result = response.json()
                if result.get('success'):
                    print(f"🎉 Block #{block_data.get('index')} successfully added to blockchain!")
                    print(f"   Block hash: {result.get('block_hash', '')[:16]}...")
                    print(f"   Transactions count: {result.get('transactions_count', 0)}")
                    print(f"   Miner: {result.get('miner', 'unknown')}")
                    return True
                else:
                    error_msg = result.get('error', 'Unknown error')
                    print(f"❌ Block submission rejected: {error_msg}")
                    return False
            else:
                print(f"❌ HTTP error {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error submitting block: {e}")
            return False
        except Exception as e:
            print(f"💥 Unexpected error submitting block: {e}")
            return False

    def _validate_block_structure(self, block_data: Dict) -> Dict:
        """Internal: Validate block structure before submission"""
        issues = []
        
        # Check required fields
        required_fields = ["index", "previous_hash", "timestamp", "transactions", "miner", "difficulty", "nonce", "hash"]
        missing_fields = [field for field in required_fields if field not in block_data]
        if missing_fields:
            issues.append(f"Missing required fields: {missing_fields}")
        
        # Check data types
        if not isinstance(block_data.get('index'), int) or block_data.get('index') < 0:
            issues.append("Index must be a non-negative integer")
        
        if not isinstance(block_data.get('transactions'), list):
            issues.append("Transactions must be a list")
        
        if not isinstance(block_data.get('difficulty'), int) or block_data.get('difficulty') < 0:
            issues.append("Difficulty must be a non-negative integer")
        
        if not isinstance(block_data.get('nonce'), int) or block_data.get('nonce') < 0:
            issues.append("Nonce must be a non-negative integer")
        
        # Check hash meets difficulty requirement
        block_hash = block_data.get('hash', '')
        difficulty = block_data.get('difficulty', 0)
        if difficulty > 0 and not block_hash.startswith('0' * difficulty):
            issues.append(f"Hash doesn't meet difficulty {difficulty}: {block_hash[:16]}...")
        
        # Check hash length (should be 64 chars for SHA-256)
        if len(block_hash) != 64:
            issues.append(f"Hash should be 64 characters, got {len(block_hash)}")
        
        # Check previous hash format
        previous_hash = block_data.get('previous_hash', '')
        if len(previous_hash) != 64 and previous_hash != '0' * 64:  # Allow genesis block
            issues.append(f"Previous hash should be 64 characters, got {len(previous_hash)}")
        
        # Check timestamp is reasonable
        current_time = time.time()
        block_time = block_data.get('timestamp', 0)
        if block_time > current_time + 300:  # 5 minutes in future
            issues.append(f"Block timestamp is in the future")
        if block_time < current_time - 86400:  # 24 hours in past  
            issues.append(f"Block timestamp is too far in the past")
        
        # Validate transactions structure
        transactions = block_data.get('transactions', [])
        for i, tx in enumerate(transactions):
            if not isinstance(tx, dict):
                issues.append(f"Transaction {i} is not a dictionary")
                continue
            
            tx_type = tx.get('type')
            if not tx_type:
                issues.append(f"Transaction {i} missing 'type' field")
            
            # Basic transaction validation
            if tx_type == 'GTX_Genesis':
                required_tx_fields = ['serial_number', 'denomination', 'issued_to', 'timestamp', 'hash']
                missing_tx_fields = [field for field in required_tx_fields if field not in tx]
                if missing_tx_fields:
                    issues.append(f"GTX_Genesis transaction {i} missing fields: {missing_tx_fields}")
            
            elif tx_type == 'reward':
                required_tx_fields = ['to', 'amount', 'timestamp', 'hash']
                missing_tx_fields = [field for field in required_tx_fields if field not in tx]
                if missing_tx_fields:
                    issues.append(f"Reward transaction {i} missing fields: {missing_tx_fields}")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'block_info': {
                'index': block_data.get('index'),
                'hash_preview': block_data.get('hash', '')[:16] + '...',
                'transaction_count': len(transactions),
                'difficulty': block_data.get('difficulty'),
                'miner': block_data.get('miner'),
                'nonce': block_data.get('nonce')
            }
        }
    def _find_address_transactions(self, block: Dict, address: str) -> List[Dict]:
        """Find transactions in block that involve the address"""
        transactions = []
        address_lower = address.lower()
        
        # Check block reward
        miner = block.get('miner', '').lower()
        if miner == address_lower:
            reward_tx = {
                'type': 'reward',
                'from': 'network',
                'to': address,
                'amount': block.get('reward', 0),
                'block_height': block.get('index'),
                'timestamp': block.get('timestamp'),
                'hash': f"reward_{block.get('index')}_{address}",
                'status': 'confirmed'
            }
            transactions.append(reward_tx)
        
        # Check regular transactions
        for tx in block.get('transactions', []):
            from_addr = (tx.get('from') or '').lower()
            to_addr = (tx.get('to') or '').lower()
            
            if from_addr == address_lower or to_addr == address_lower:
                enhanced_tx = tx.copy()
                enhanced_tx['block_height'] = block.get('index')
                enhanced_tx['status'] = 'confirmed'
                transactions.append(enhanced_tx)
                
        return transactions