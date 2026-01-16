# lunalib/wallet_manager.py
"""
Unified Wallet State Manager

Provides a single source of truth for wallet balances, transaction history,
pending transactions, transfers, and rewards. Scans the blockchain once and
efficiently distributes transactions to multiple wallets while maintaining
real-time updates available to the UI.
"""

import threading
import time
from typing import Dict, List, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
from datetime import datetime


class TransactionType(Enum):
    """Types of transactions"""
    TRANSFER = "transfer"
    REWARD = "reward"
    GTX_GENESIS = "gtx_genesis"
    INCOMING = "incoming"
    OUTGOING = "outgoing"


class TransactionStatus(Enum):
    """Status of a transaction"""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"


@dataclass
class Transaction:
    """Represents a single transaction"""
    hash: str
    type: str
    from_address: str
    to_address: str
    amount: float
    fee: float = 0.0
    timestamp: int = 0
    status: str = TransactionStatus.PENDING.value
    block_height: Optional[int] = None
    confirmations: int = 0
    memo: str = ""
    direction: str = ""  # 'incoming', 'outgoing', or '' for self
    
    def to_dict(self) -> Dict:
        """Convert transaction to dictionary"""
        return asdict(self)


@dataclass
class WalletBalance:
    """Wallet balance information"""
    total_balance: float = 0.0
    available_balance: float = 0.0
    pending_incoming: float = 0.0
    pending_outgoing: float = 0.0
    confirmed_balance: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class WalletState:
    """Complete state for a single wallet"""
    address: str
    balance: WalletBalance = field(default_factory=WalletBalance)
    confirmed_transactions: List[Transaction] = field(default_factory=list)
    pending_transactions: List[Transaction] = field(default_factory=list)
    confirmed_transfers: List[Transaction] = field(default_factory=list)
    pending_transfers: List[Transaction] = field(default_factory=list)
    rewards: List[Transaction] = field(default_factory=list)
    genesis_transactions: List[Transaction] = field(default_factory=list)
    last_updated: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary, converting transactions to dicts"""
        return {
            'address': self.address,
            'balance': self.balance.to_dict(),
            'confirmed_transactions': [tx.to_dict() for tx in self.confirmed_transactions],
            'pending_transactions': [tx.to_dict() for tx in self.pending_transactions],
            'confirmed_transfers': [tx.to_dict() for tx in self.confirmed_transfers],
            'pending_transfers': [tx.to_dict() for tx in self.pending_transfers],
            'rewards': [tx.to_dict() for tx in self.rewards],
            'genesis_transactions': [tx.to_dict() for tx in self.genesis_transactions],
            'last_updated': self.last_updated
        }


class WalletStateManager:
    """
    Unified wallet manager that:
    1. Scans blockchain once for all wallets
    2. Efficiently categorizes transactions (transfers, rewards, genesis)
    3. Tracks pending transactions from mempool
    4. Maintains real-time balance calculations
    5. Provides immediate UI updates via callbacks
    """
    
    def __init__(self):
        self.wallet_states: Dict[str, WalletState] = {}
        self.state_lock = threading.RLock()
        self.balance_callbacks: List[Callable] = []
        self.transaction_callbacks: List[Callable] = []
        from lunalib.utils.console import print_info, print_success
        # Cache for pending transactions to avoid duplicate processing
        self.processed_pending_hashes: Set[str] = set()
        self.processed_confirmed_hashes: Set[str] = set()
        # Sync control
        self.last_sync_time = 0
        self.sync_in_progress = False
        self.last_blockchain_height = 0
        
    # =========================================================================
    # Address normalization
    # =========================================================================
    
    def _normalize_address(self, addr: str) -> str:
        """Normalize address for comparison"""
        if not addr:
            return ''
        addr_str = str(addr).strip("'\" ").lower()
        return addr_str[4:] if addr_str.startswith('lun_') else addr_str
    
    def _addresses_match(self, addr1: str, addr2: str) -> bool:
        """Check if two addresses match (after normalization)"""
        return self._normalize_address(addr1) == self._normalize_address(addr2)
    
    # =========================================================================
    # Wallet management
    # =========================================================================
    
    def register_wallet(self, address: str) -> WalletState:
        """Register a new wallet to track"""
        with self.state_lock:
            if address not in self.wallet_states:
                self.wallet_states[address] = WalletState(address=address)
                print_success(f"📱 Registered wallet: {address}")
            return self.wallet_states[address]
    
    def register_wallets(self, addresses: List[str]) -> Dict[str, WalletState]:
        """Register multiple wallets"""
        states = {}
        for addr in addresses:
            states[addr] = self.register_wallet(addr)
        return states
    
    def get_wallet_state(self, address: str) -> Optional[WalletState]:
        """Get current state of a wallet"""
        with self.state_lock:
            return self.wallet_states.get(address)
    
    def get_all_wallet_states(self) -> Dict[str, WalletState]:
        """Get states for all registered wallets"""
        with self.state_lock:
            return dict(self.wallet_states)
    
    # =========================================================================
    # Transaction categorization and processing
    # =========================================================================
    
    def _categorize_confirmed_transaction(self, tx: Transaction, address: str) -> List[str]:
        """
        Categorize a confirmed transaction and return which lists to add it to.
        Returns list of category names.
        """
        categories = ['confirmed_transactions']
        
        tx_type_lower = (tx.type or '').lower()
        
        # Categorize by type
        if tx_type_lower == 'reward' or tx.from_address == 'network':
            categories.append('rewards')
        elif tx_type_lower == 'gtx_genesis':
            categories.append('genesis_transactions')
        elif tx_type_lower in ['transfer', '']:
            categories.append('confirmed_transfers')
        
        return categories
    
    def _categorize_pending_transaction(self, tx: Transaction, address: str) -> List[str]:
        """
        Categorize a pending transaction and return which lists to add it to.
        Returns list of category names.
        """
        categories = ['pending_transactions']
        
        tx_type_lower = (tx.type or '').lower()
        
        # Categorize by type
        if tx_type_lower == 'reward':
            categories.append('rewards')
        elif tx_type_lower == 'gtx_genesis':
            categories.append('genesis_transactions')
        elif tx_type_lower in ['transfer', '']:
            categories.append('pending_transfers')
        
        return categories
    
    def _process_blockchain_transactions(self, raw_transactions: Dict[str, List[Dict]]) -> Dict[str, List[Transaction]]:
        """
        Convert raw blockchain transactions to Transaction objects and
        categorize them by address and type.
        
        Returns mapping of address -> list of Transaction objects
        """
        processed = {}
        
        for address, raw_txs in raw_transactions.items():
            transactions = []
            
            for raw_tx in raw_txs:
                try:
                    # Determine transaction direction
                    direction = ""
                    if self._addresses_match(raw_tx.get('from'), address):
                        direction = 'outgoing'
                    if self._addresses_match(raw_tx.get('to'), address):
                        direction = 'incoming'
                    
                    # Create Transaction object
                    tx = Transaction(
                        hash=raw_tx.get('hash', ''),
                        type=raw_tx.get('type', 'transfer'),
                        from_address=raw_tx.get('from', ''),
                        to_address=raw_tx.get('to', ''),
                        amount=float(raw_tx.get('amount', 0)),
                        fee=float(raw_tx.get('fee', 0)),
                        timestamp=int(raw_tx.get('timestamp', 0)),
                        status=TransactionStatus.CONFIRMED.value,
                        block_height=raw_tx.get('block_height'),
                        confirmations=raw_tx.get('confirmations', 1),
                        memo=raw_tx.get('memo', ''),
                        direction=direction
                    )
                    
                    # Skip if we've already processed this
                    if tx.hash not in self.processed_confirmed_hashes:
                        transactions.append(tx)
                        self.processed_confirmed_hashes.add(tx.hash)
                        
                except Exception as e:
                    print(f"⚠️  Error processing transaction {raw_tx.get('hash')}: {e}")
                    continue
            
            if transactions:
                processed[address] = transactions
        
        return processed
    
    def _process_mempool_transactions(self, raw_transactions: Dict[str, List[Dict]]) -> Dict[str, List[Transaction]]:
        """
        Convert raw mempool transactions to Transaction objects.
        
        Returns mapping of address -> list of Transaction objects
        """
        processed = {}
        
        for address, raw_txs in raw_transactions.items():
            transactions = []
            
            for raw_tx in raw_txs:
                try:
                    # Determine transaction direction
                    direction = ""
                    if self._addresses_match(raw_tx.get('from'), address):
                        direction = 'outgoing'
                    if self._addresses_match(raw_tx.get('to'), address):
                        direction = 'incoming'
                    
                    # Create Transaction object
                    tx = Transaction(
                        hash=raw_tx.get('hash', ''),
                        type=raw_tx.get('type', 'transfer'),
                        from_address=raw_tx.get('from', ''),
                        to_address=raw_tx.get('to', ''),
                        amount=float(raw_tx.get('amount', 0)),
                        fee=float(raw_tx.get('fee', 0)),
                        timestamp=int(raw_tx.get('timestamp', 0)),
                        status=TransactionStatus.PENDING.value,
                        memo=raw_tx.get('memo', ''),
                        direction=direction
                    )
                    
                    # Skip if we've already processed this
                    if tx.hash not in self.processed_pending_hashes:
                        transactions.append(tx)
                        self.processed_pending_hashes.add(tx.hash)
                        
                except Exception as e:
                    print(f"⚠️  Error processing pending transaction {raw_tx.get('hash')}: {e}")
                    continue
            
            if transactions:
                processed[address] = transactions
        
        return processed
    
    # =========================================================================
    # Balance calculation
    # =========================================================================
    
    def _calculate_balance_from_transactions(self, address: str, 
                                           confirmed_txs: List[Transaction],
                                           pending_txs: List[Transaction]) -> WalletBalance:
        """Calculate wallet balance from confirmed and pending transactions"""
        
        confirmed_balance = 0.0
        pending_incoming = 0.0
        pending_outgoing = 0.0
        
        # Process confirmed transactions
        for tx in confirmed_txs:
            if self._addresses_match(tx.from_address, address):
                # Outgoing: subtract amount and fee
                confirmed_balance -= (tx.amount + tx.fee)
            elif self._addresses_match(tx.to_address, address):
                # Incoming: add amount
                confirmed_balance += tx.amount
            elif tx.type == 'reward' or tx.from_address == 'network':
                # Reward received
                confirmed_balance += tx.amount
        
        # Process pending transactions
        for tx in pending_txs:
            if self._addresses_match(tx.from_address, address):
                # Pending outgoing
                pending_outgoing += (tx.amount + tx.fee)
            elif self._addresses_match(tx.to_address, address):
                # Pending incoming
                pending_incoming += tx.amount
        
        # Calculate derived balances
        confirmed_balance = max(0.0, confirmed_balance)
        total_balance = confirmed_balance + pending_incoming
        available_balance = max(0.0, confirmed_balance - pending_outgoing)
        
        return WalletBalance(
            total_balance=total_balance,
            available_balance=available_balance,
            pending_incoming=pending_incoming,
            pending_outgoing=pending_outgoing,
            confirmed_balance=confirmed_balance
        )
    
    # =========================================================================
    # Sync operations (blockchain + mempool)
    # =========================================================================
    
    def sync_wallets_from_sources(self, blockchain_transactions: Dict[str, List[Dict]],
                                   mempool_transactions: Dict[str, List[Dict]]):
        """
        Main sync method: takes raw blockchain and mempool data and updates all wallets.
        
        This is designed to be called with data from:
        - blockchain.scan_transactions_for_addresses()
        - mempool.get_pending_transactions_for_addresses()
        
        The method efficiently:
        1. Processes and categorizes transactions
        2. Updates all wallet states
        3. Calculates balances
        4. Triggers callbacks for UI updates
        """
        
        with self.state_lock:
            print_info(f"\n🔄 Syncing wallets...")
            sync_start = time.time()
            
            # Process blockchain transactions
            confirmed_map = self._process_blockchain_transactions(blockchain_transactions)
            
            # Process mempool transactions
            pending_map = self._process_mempool_transactions(mempool_transactions)
            
            # Get all addresses we're tracking
            all_addresses = set(self.wallet_states.keys())
            
            # Update each wallet
            for address in all_addresses:
                state = self.wallet_states[address]
                
                # Get transactions for this wallet
                confirmed_txs = confirmed_map.get(address, [])
                pending_txs = pending_map.get(address, [])
                
                # Clear old transactions (we'll repopulate from fresh data)
                state.confirmed_transactions = confirmed_txs.copy()
                state.pending_transactions = pending_txs.copy()
                
                # Clear specialized lists and repopulate
                state.confirmed_transfers = []
                state.pending_transfers = []
                state.rewards = []
                state.genesis_transactions = []
                
                # Categorize confirmed transactions
                for tx in confirmed_txs:
                    categories = self._categorize_confirmed_transaction(tx, address)
                    for category in categories:
                        if category == 'confirmed_transfers':
                            state.confirmed_transfers.append(tx)
                        elif category == 'rewards':
                            state.rewards.append(tx)
                        elif category == 'genesis_transactions':
                            state.genesis_transactions.append(tx)
                
                # Categorize pending transactions
                for tx in pending_txs:
                    categories = self._categorize_pending_transaction(tx, address)
                    for category in categories:
                        if category == 'pending_transfers':
                            state.pending_transfers.append(tx)
                        elif category == 'rewards':
                            if tx not in state.rewards:
                                state.rewards.append(tx)
                        elif category == 'genesis_transactions':
                            if tx not in state.genesis_transactions:
                                state.genesis_transactions.append(tx)
                
                # Calculate new balance
                state.balance = self._calculate_balance_from_transactions(
                    address, confirmed_txs, pending_txs
                )
                
                # Update timestamp
                state.last_updated = time.time()
            
            sync_time = time.time() - sync_start
            print_success(f"✅ Sync complete in {sync_time:.2f}s")
            
            # Trigger callbacks
            self._trigger_balance_updates()
            self._trigger_transaction_updates()
    
    def sync_wallets_background(self, get_blockchain_data: Callable,
                               get_mempool_data: Callable,
                               poll_interval: int = 30):
        """
        Start a background thread that periodically syncs wallet data.
        
        Parameters:
            get_blockchain_data: Callable that returns Dict[str, List[Dict]]
            get_mempool_data: Callable that returns Dict[str, List[Dict]]
            poll_interval: Seconds between syncs
        """
        
        def sync_loop():
            while True:
                try:
                    addresses = list(self.wallet_states.keys())
                    if addresses:
                        blockchain_txs = get_blockchain_data(addresses)
                        mempool_txs = get_mempool_data(addresses)
                        self.sync_wallets_from_sources(blockchain_txs, mempool_txs)
                    
                    time.sleep(poll_interval)
                except Exception as e:
                    print(f"⚠️  Background sync error: {e}")
                    time.sleep(poll_interval)
        
        thread = threading.Thread(target=sync_loop, daemon=True)
        thread.start()
        print_info(f"🔄 Started background sync thread (interval: {poll_interval}s)")
    
    # =========================================================================
    # Callbacks for UI updates
    # =========================================================================
    
    def on_balance_update(self, callback: Callable):
        """Register callback for balance updates"""
        self.balance_callbacks.append(callback)
    
    def on_transaction_update(self, callback: Callable):
        """Register callback for transaction updates"""
        self.transaction_callbacks.append(callback)
    
    def _trigger_balance_updates(self):
        """Trigger all balance update callbacks"""
        with self.state_lock:
            balance_data = {}
            for addr, state in self.wallet_states.items():
                balance_data[addr] = state.balance.to_dict()
        
        for callback in self.balance_callbacks:
            try:
                callback(balance_data)
            except Exception as e:
                print(f"⚠️  Balance callback error: {e}")
    
    def _trigger_transaction_updates(self):
        """Trigger all transaction update callbacks"""
        with self.state_lock:
            transaction_data = {}
            for addr, state in self.wallet_states.items():
                transaction_data[addr] = {
                    'confirmed': [tx.to_dict() for tx in state.confirmed_transactions],
                    'pending': [tx.to_dict() for tx in state.pending_transactions],
                    'transfers': {
                        'confirmed': [tx.to_dict() for tx in state.confirmed_transfers],
                        'pending': [tx.to_dict() for tx in state.pending_transfers],
                    },
                    'rewards': [tx.to_dict() for tx in state.rewards],
                }
        
        for callback in self.transaction_callbacks:
            try:
                callback(transaction_data)
            except Exception as e:
                print(f"⚠️  Transaction callback error: {e}")
    
    # =========================================================================
    # Query methods for UI
    # =========================================================================
    
    def get_balance(self, address: str) -> Optional[Dict]:
        """Get balance for a specific wallet"""
        state = self.get_wallet_state(address)
        if state:
            return state.balance.to_dict()
        return None
    
    def get_all_balances(self) -> Dict[str, Dict]:
        """Get balances for all wallets"""
        with self.state_lock:
            balances = {}
            for addr, state in self.wallet_states.items():
                balances[addr] = state.balance.to_dict()
            return balances
    
    def get_transactions(self, address: str, transaction_type: str = 'all') -> List[Dict]:
        """
        Get transactions for a wallet.
        
        Types: 'all', 'confirmed', 'pending', 'transfers', 'rewards', 'genesis'
        """
        state = self.get_wallet_state(address)
        if not state:
            return []
        
        result = []
        
        if transaction_type in ['all', 'confirmed']:
            result.extend([tx.to_dict() for tx in state.confirmed_transactions])
        
        if transaction_type in ['all', 'pending']:
            result.extend([tx.to_dict() for tx in state.pending_transactions])
        
        if transaction_type in ['transfers']:
            result.extend([tx.to_dict() for tx in state.confirmed_transfers])
            result.extend([tx.to_dict() for tx in state.pending_transfers])
        
        if transaction_type in ['all', 'rewards']:
            result.extend([tx.to_dict() for tx in state.rewards])
        
        if transaction_type in ['all', 'genesis']:
            result.extend([tx.to_dict() for tx in state.genesis_transactions])
        
        # Sort by timestamp (most recent first)
        result.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return result
    
    def get_wallet_summary(self, address: str) -> Optional[Dict]:
        """Get complete summary for a wallet (balance + all transaction types)"""
        state = self.get_wallet_state(address)
        if not state:
            return None
        
        return {
            'address': address,
            'balance': state.balance.to_dict(),
            'transaction_counts': {
                'confirmed': len(state.confirmed_transactions),
                'pending': len(state.pending_transactions),
                'transfers_confirmed': len(state.confirmed_transfers),
                'transfers_pending': len(state.pending_transfers),
                'rewards': len(state.rewards),
                'genesis': len(state.genesis_transactions),
            },
            'transactions': {
                'confirmed': [tx.to_dict() for tx in state.confirmed_transactions[-10:]],  # Last 10
                'pending': [tx.to_dict() for tx in state.pending_transactions],
                'rewards': [tx.to_dict() for tx in state.rewards[-10:]],
            },
            'last_updated': state.last_updated
        }
    
    def get_all_summaries(self) -> Dict[str, Dict]:
        """Get summaries for all registered wallets"""
        with self.state_lock:
            summaries = {}
            for address in self.wallet_states:
                summary = self.get_wallet_summary(address)
                if summary:
                    summaries[address] = summary
            return summaries
    
    # =========================================================================
    # Utility methods
    # =========================================================================
    
    def clear_all_caches(self):
        """Clear all transaction caches (for testing)"""
        with self.state_lock:
            self.processed_pending_hashes.clear()
            self.processed_confirmed_hashes.clear()
    
    def reset_wallet(self, address: str):
        """Reset a wallet to empty state"""
        with self.state_lock:
            if address in self.wallet_states:
                self.wallet_states[address] = WalletState(address=address)
    
    def remove_wallet(self, address: str):
        """Remove a wallet from tracking"""
        with self.state_lock:
            if address in self.wallet_states:
                del self.wallet_states[address]


# Global singleton instance
_wallet_state_manager = WalletStateManager()


def get_wallet_manager() -> WalletStateManager:
    """Get the global wallet state manager instance"""
    return _wallet_state_manager
