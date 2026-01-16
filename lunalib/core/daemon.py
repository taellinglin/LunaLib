# lunalib/core/daemon.py
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Callable
import json
from datetime import datetime


class BlockchainDaemon:
    """
    Primary blockchain daemon that manages the authoritative blockchain state.
    Validates all transactions, manages peer registry, and serves as source of truth.
    """
    
    def __init__(self, blockchain_manager, mempool_manager, security_manager=None, max_workers=5):
        self.blockchain = blockchain_manager
        self.mempool = mempool_manager
        self.security = security_manager
        
        # Initialize difficulty system for validation
        from ..mining.difficulty import DifficultySystem
        self.difficulty_system = DifficultySystem()
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DaemonWorker")
        self._async_tasks = {}  # Track async tasks
        
        # Peer registry
        self.peers = {}  # {node_id: peer_info}
        self.peer_lock = threading.Lock()
        
        # Daemon state
        self.is_running = False
        self.validation_thread = None
        self.cleanup_thread = None
        
        # Statistics
        self.stats = {
            'blocks_validated': 0,
            'transactions_validated': 0,
            'peers_registered': 0,
            'start_time': time.time()
        }
    
    def start(self):
        """Start the blockchain daemon"""
        if self.is_running:
            return
        
        self.is_running = True
        print("🏛️  Blockchain Daemon starting...")
        
        # Start background threads
        self.validation_thread = threading.Thread(target=self._validation_loop, daemon=True)
        self.validation_thread.start()
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        print("✅ Blockchain Daemon started")
    
    def stop(self):
        """Stop the blockchain daemon"""
        self.is_running = False
        
        if self.validation_thread:
            self.validation_thread.join(timeout=5)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        
        # Shutdown executor
        print("🛑 Shutting down daemon executor...")
        self.executor.shutdown(wait=True)
        
        print("🛑 Blockchain Daemon stopped")
    
    def register_peer(self, peer_info: Dict) -> Dict:
        """
        Register a new peer node.
        Returns: {'success': bool, 'node_id': str, 'message': str}
        """
        try:
            node_id = peer_info.get('node_id')
            if not node_id:
                return {'success': False, 'message': 'Missing node_id'}
            
            with self.peer_lock:
                self.peers[node_id] = {
                    'node_id': node_id,
                    'registered_at': time.time(),
                    'last_seen': time.time(),
                    'capabilities': peer_info.get('capabilities', []),
                    'url': peer_info.get('url'),
                    'version': peer_info.get('version', 'unknown')
                }
                
                self.stats['peers_registered'] += 1
            
            print(f"👤 New peer registered: {node_id}")
            return {
                'success': True,
                'node_id': node_id,
                'message': 'Peer registered successfully'
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def unregister_peer(self, node_id: str) -> Dict:
        """
        Unregister a peer node.
        Returns: {'success': bool, 'message': str}
        """
        try:
            with self.peer_lock:
                if node_id in self.peers:
                    del self.peers[node_id]
                    print(f"👋 Peer unregistered: {node_id}")
                    return {'success': True, 'message': 'Peer unregistered'}
                else:
                    return {'success': False, 'message': 'Peer not found'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def get_peer_list(self, exclude_node_id: Optional[str] = None) -> List[Dict]:
        """
        Get list of registered peers.
        exclude_node_id: Optional node ID to exclude from results
        """
        with self.peer_lock:
            peer_list = []
            for node_id, peer_info in self.peers.items():
                if exclude_node_id and node_id == exclude_node_id:
                    continue
                
                peer_list.append({
                    'node_id': peer_info['node_id'],
                    'url': peer_info.get('url'),
                    'last_seen': peer_info['last_seen'],
                    'capabilities': peer_info.get('capabilities', [])
                })
            
            return peer_list
    
    def update_peer_heartbeat(self, node_id: str):
        """Update peer's last seen timestamp"""
        with self.peer_lock:
            if node_id in self.peers:
                self.peers[node_id]['last_seen'] = time.time()
    
    def validate_block_async(self, block: Dict, callback: Callable = None) -> str:
        """Async version: Validate block in background thread
        
        Returns: task_id that can be used to check status
        """
        task_id = f"validate_block_{block.get('index', 'unknown')}_{int(time.time())}"
        
        def _validate_task():
            try:
                result = self.validate_block(block)
                if callback:
                    callback(success=result['valid'], result=result, error=None if result['valid'] else result['message'])
                return result
            except Exception as e:
                print(f"❌ Async validation error: {e}")
                if callback:
                    callback(success=False, result=None, error=str(e))
                return {'valid': False, 'message': str(e), 'errors': [str(e)]}
        
        future = self.executor.submit(_validate_task)
        self._async_tasks[task_id] = future
        print(f"🔄 Started async block validation: {task_id}")
        return task_id
    
    def validate_block(self, block: Dict) -> Dict:
        """
        Validate a block submitted by a peer or miner.
        Returns: {'valid': bool, 'message': str, 'errors': List[str]}
        """
        errors = []
        
        try:
            # Basic structure validation using difficulty system
            is_valid, error_msg = self.difficulty_system.validate_block_structure(block)
            if not is_valid:
                errors.append(error_msg)
                return {'valid': False, 'message': 'Invalid block structure', 'errors': errors}
            
            # Validate block index
            latest_block = self.blockchain.get_latest_block()
            if latest_block:
                expected_index = latest_block.get('index', 0) + 1
                if block['index'] != expected_index:
                    errors.append(f"Invalid block index: expected {expected_index}, got {block['index']}")
            
            # Validate previous hash
            if latest_block and block['previous_hash'] != latest_block.get('hash'):
                expected_hash = latest_block.get('hash', '')
                actual_hash = block.get('previous_hash', '')
                errors.append(f"Previous hash mismatch: expected {expected_hash[:16]}..., got {actual_hash[:16]}...")
            
            # Validate hash meets difficulty requirement using difficulty system
            difficulty = block.get('difficulty', 0)
            block_hash = block.get('hash', '')
            
            if not self.difficulty_system.validate_block_hash(block_hash, difficulty):
                errors.append(f"Hash doesn't meet difficulty {difficulty} requirement (needs {difficulty} leading zeros)")
            
            # Validate reward matches difficulty
            # Empty blocks use LINEAR system (difficulty = reward)
            # Regular blocks use EXPONENTIAL system (10^(difficulty-1))
            transactions = block.get('transactions', [])
            is_empty_block = len(transactions) == 1 and transactions[0].get('is_empty_block', False)
            
            if is_empty_block:
                # Empty block: linear reward (difficulty 1 = 1 LKC, difficulty 2 = 2 LKC, etc.)
                expected_reward = float(difficulty)
                reward_type = "Linear"
            else:
                # Regular block: exponential reward (10^(difficulty-1))
                expected_reward = self.difficulty_system.calculate_block_reward(difficulty)
                reward_type = "Exponential"
            
            actual_reward = block.get('reward', 0)
            
            # Allow small tolerance for floating point comparison
            if abs(actual_reward - expected_reward) > 0.01:
                errors.append(f"Reward mismatch ({reward_type}): expected {expected_reward} LKC for difficulty {difficulty}, got {actual_reward} LKC")
            
            # Validate transactions
            for tx in block.get('transactions', []):
                tx_validation = self.validate_transaction(tx)
                if not tx_validation['valid']:
                    errors.append(f"Invalid transaction: {tx_validation['message']}")
            
            if errors:
                return {'valid': False, 'message': 'Block validation failed', 'errors': errors}
            
            self.stats['blocks_validated'] += 1
            print(f"✅ Block #{block['index']} validated: Difficulty {difficulty}, Reward {actual_reward} LKC, Hash {block_hash[:16]}...")
            return {'valid': True, 'message': 'Block is valid', 'errors': []}
            
        except Exception as e:
            return {'valid': False, 'message': f'Validation error: {str(e)}', 'errors': [str(e)]}
    
    def validate_transaction(self, transaction: Dict) -> Dict:
        """
        Validate a transaction submitted by a peer.
        Returns: {'valid': bool, 'message': str, 'errors': List[str]}
        """
        errors = []
        
        try:
            # Basic validation
            tx_type = transaction.get('type')
            if not tx_type:
                errors.append("Missing transaction type")
            
            # Type-specific validation
            if tx_type == 'transaction':
                required = ['from', 'to', 'amount', 'timestamp']
                for field in required:
                    if field not in transaction:
                        errors.append(f"Missing field: {field}")
                
                # Validate amount
                amount = transaction.get('amount', 0)
                if amount <= 0:
                    errors.append("Invalid amount: must be positive")
            
            elif tx_type == 'genesis_bill':
                if 'denomination' not in transaction:
                    errors.append("Missing denomination for genesis bill")
            
            elif tx_type == 'reward':
                required = ['to', 'amount']
                for field in required:
                    if field not in transaction:
                        errors.append(f"Missing field: {field}")
            
            # Security validation if available
            if self.security and not errors:
                try:
                    # Use security manager for advanced validation
                    # security_result = self.security.validate_transaction(transaction)
                    pass
                except Exception as e:
                    errors.append(f"Security validation error: {e}")
            
            if errors:
                return {'valid': False, 'message': 'Transaction validation failed', 'errors': errors}
            
            self.stats['transactions_validated'] += 1
            return {'valid': True, 'message': 'Transaction is valid', 'errors': []}
            
        except Exception as e:
            return {'valid': False, 'message': f'Validation error: {str(e)}', 'errors': [str(e)]}
    
    def process_incoming_block_async(self, block: Dict, from_peer: Optional[str] = None, callback: Callable = None) -> str:
        """Async version: Process incoming block in background thread
        
        Returns: task_id that can be used to check status
        """
        task_id = f"process_block_{block.get('index', 'unknown')}_{int(time.time())}"
        
        def _process_task():
            try:
                result = self.process_incoming_block(block, from_peer)
                if callback:
                    callback(success=result.get('success', False), result=result, error=None if result.get('success') else result.get('message'))
                return result
            except Exception as e:
                print(f"❌ Async block processing error: {e}")
                if callback:
                    callback(success=False, result=None, error=str(e))
                return {'success': False, 'message': str(e)}
        
        future = self.executor.submit(_process_task)
        self._async_tasks[task_id] = future
        print(f"🔄 Started async block processing: {task_id}")
        return task_id
    
    def process_incoming_block(self, block: Dict, from_peer: Optional[str] = None) -> Dict:
        """
        Process an incoming block from P2P network.
        Validates and adds to blockchain if valid.
        """
        try:
            # Validate block
            validation = self.validate_block(block)
            
            if not validation['valid']:
                print(f"❌ Invalid block from peer {from_peer}: {validation['message']}")
                return validation
            
            # Add to blockchain
            success = self.blockchain.submit_mined_block(block)
            
            if success:
                print(f"✅ Block #{block['index']} accepted from peer {from_peer}")
                
                # Broadcast to other peers
                self._broadcast_block_to_peers(block, exclude=from_peer)
                
                return {'success': True, 'message': 'Block accepted and propagated'}
            else:
                return {'success': False, 'message': 'Block submission failed'}
                
        except Exception as e:
            return {'success': False, 'message': f'Processing error: {str(e)}'}
    
    def process_incoming_transaction(self, transaction: Dict, from_peer: Optional[str] = None) -> Dict:
        """
        Process an incoming transaction from P2P network.
        Validates and adds to mempool if valid.
        """
        try:
            # Validate transaction
            validation = self.validate_transaction(transaction)
            
            if not validation['valid']:
                print(f"❌ Invalid transaction from peer {from_peer}: {validation['message']}")
                return validation
            
            # Add to mempool
            # self.mempool.add_transaction(transaction)
            print(f"✅ Transaction accepted from peer {from_peer}")
            
            # Broadcast to other peers
            self._broadcast_transaction_to_peers(transaction, exclude=from_peer)
            
            return {'success': True, 'message': 'Transaction accepted and propagated'}
            
        except Exception as e:
            return {'success': False, 'message': f'Processing error: {str(e)}'}
    
    def _broadcast_block_to_peers(self, block: Dict, exclude: Optional[str] = None):
        """Broadcast block to all registered peers except excluded one"""
        with self.peer_lock:
            for node_id, peer_info in self.peers.items():
                if node_id == exclude:
                    continue
                
                # Send block to peer (implementation depends on transport)
                # This would typically use HTTP POST or WebSocket
                pass
    
    def _broadcast_transaction_to_peers(self, transaction: Dict, exclude: Optional[str] = None):
        """Broadcast transaction to all registered peers except excluded one"""
        with self.peer_lock:
            for node_id, peer_info in self.peers.items():
                if node_id == exclude:
                    continue
                
                # Send transaction to peer
                pass
    
    def _validation_loop(self):
        """Background thread for continuous validation"""
        while self.is_running:
            try:
                # Periodic mempool validation
                # Remove invalid transactions from mempool
                time.sleep(30)
                
            except Exception as e:
                print(f"❌ Validation loop error: {e}")
                time.sleep(10)
    
    def _cleanup_loop(self):
        """Background thread for peer cleanup"""
        while self.is_running:
            try:
                current_time = time.time()
                timeout = 300  # 5 minutes
                
                with self.peer_lock:
                    inactive_peers = []
                    for node_id, peer_info in self.peers.items():
                        if current_time - peer_info['last_seen'] > timeout:
                            inactive_peers.append(node_id)
                    
                    # Remove inactive peers
                    for node_id in inactive_peers:
                        del self.peers[node_id]
                        print(f"🧹 Removed inactive peer: {node_id}")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                print(f"❌ Cleanup loop error: {e}")
                time.sleep(60)
    
    def get_task_status(self, task_id: str) -> Dict:
        """Check status of an async task
        
        Returns: {'status': 'running'|'completed'|'failed'|'not_found', 'result': any, 'error': str}
        """
        if task_id not in self._async_tasks:
            return {'status': 'not_found', 'result': None, 'error': 'Task not found'}
        
        future = self._async_tasks[task_id]
        
        if future.running():
            return {'status': 'running', 'result': None, 'error': None}
        elif future.done():
            try:
                result = future.result(timeout=0)
                return {'status': 'completed', 'result': result, 'error': None}
            except Exception as e:
                return {'status': 'failed', 'result': None, 'error': str(e)}
        else:
            return {'status': 'pending', 'result': None, 'error': None}
    
    def get_active_tasks(self) -> List[str]:
        """Get list of active task IDs"""
        return [task_id for task_id, future in self._async_tasks.items() if future.running()]
    
    def cleanup_completed_tasks(self):
        """Remove completed tasks from tracking"""
        completed = [task_id for task_id, future in self._async_tasks.items() if future.done()]
        for task_id in completed:
            del self._async_tasks[task_id]
        if completed:
            print(f"🧹 Cleaned up {len(completed)} completed tasks")
    
    def get_stats(self) -> Dict:
        """Get daemon statistics"""
        uptime = time.time() - self.stats['start_time']
        
        with self.peer_lock:
            peer_count = len(self.peers)
        
        return {
            'uptime_seconds': uptime,
            'blocks_validated': self.stats['blocks_validated'],
            'transactions_validated': self.stats['transactions_validated'],
            'peers_registered': self.stats['peers_registered'],
            'active_peers': peer_count,
            'mempool_size': len(self.mempool.get_pending_transactions()) if self.mempool else 0
        }
    
    def get_blockchain_state(self) -> Dict:
        """Get current blockchain state for peers"""
        latest_block = self.blockchain.get_latest_block()
        height = self.blockchain.get_blockchain_height()
        
        return {
            'height': height,
            'latest_block': latest_block,
            'mempool_size': len(self.mempool.get_pending_transactions()) if self.mempool else 0,
            'timestamp': time.time()
        }
