# lunalib/wallet_sync_helper.py
"""
Wallet Sync Helper

Provides integration between LunaWallet, BlockchainManager, MempoolManager,
and the WalletStateManager for seamless real-time balance and transaction updates.
"""

from typing import List, Dict, Optional, Callable
from .wallet_manager import get_wallet_manager


class WalletSyncHelper:
    """
    Helper class to sync LunaWallet with WalletStateManager using data from
    BlockchainManager and MempoolManager.
    """
    
    def __init__(self, wallet=None, blockchain=None, mempool=None):
        """
        Initialize sync helper.
        
        Parameters:
            wallet: LunaWallet instance
            blockchain: BlockchainManager instance
            mempool: MempoolManager instance
        """
        self.wallet = wallet
        self.blockchain = blockchain
        self.mempool = mempool
        self.state_manager = get_wallet_manager()
        
    def register_wallets_from_lunawallet(self) -> Dict:
        """Register all wallets from LunaWallet into the state manager"""
        if not self.wallet:
            print("⚠️  No wallet instance provided")
            return {}
        
        addresses = list(self.wallet.wallets.keys())
        if not addresses:
            print("⚠️  No wallets registered in LunaWallet")
            return {}
        
        print(f"📱 Registering {len(addresses)} wallets with state manager...")
        states = self.state_manager.register_wallets(addresses)
        print(f"✅ Registered {len(states)} wallets")
        
        return states
    
    def sync_wallets_now(self) -> Dict:
        """
        Perform a single synchronization of all registered wallets.
        
        Returns: Dictionary of wallet addresses and their updated summaries
        """
        if not self.blockchain or not self.mempool:
            print("⚠️  Blockchain or mempool not provided")
            return {}
        
        addresses = list(self.state_manager.wallet_states.keys())
        if not addresses:
            print("⚠️  No wallets registered")
            return {}
        
        print(f"🔄 Syncing {len(addresses)} wallets...")
        
        try:
            # Get data from blockchain and mempool
            blockchain_txs = self.blockchain.scan_transactions_for_addresses(addresses)
            mempool_txs = self.mempool.get_pending_transactions_for_addresses(addresses)
            
            # Sync the state manager
            self.state_manager.sync_wallets_from_sources(blockchain_txs, mempool_txs)
            
            # Update LunaWallet balances if available
            if self.wallet:
                self._update_lunawallet_balances()
            
            # Return summaries
            return self.state_manager.get_all_summaries()
            
        except Exception as e:
            print(f"❌ Sync error: {e}")
            return {}
    
    def _update_lunawallet_balances(self):
        """Update LunaWallet instance balances from state manager"""
        if not self.wallet:
            return
        
        balances = self.state_manager.get_all_balances()
        
        for address, balance_data in balances.items():
            if address in self.wallet.wallets:
                wallet_data = self.wallet.wallets[address]
                wallet_data['balance'] = balance_data['confirmed_balance']
                wallet_data['available_balance'] = balance_data['available_balance']
        
        # Update current wallet if one is selected
        if self.wallet.current_wallet_address in balances:
            balance_data = balances[self.wallet.current_wallet_address]
            self.wallet.balance = balance_data['confirmed_balance']
            self.wallet.available_balance = balance_data['available_balance']
    
    def start_continuous_sync(self, poll_interval: int = 30,
                             on_balance_update: Optional[Callable] = None,
                             on_transaction_update: Optional[Callable] = None) -> None:
        """
        Start continuous synchronization in the background.
        
        Parameters:
            poll_interval: Seconds between syncs
            on_balance_update: Callback function(balance_data) for balance updates
            on_transaction_update: Callback function(transaction_data) for transaction updates
        """
        
        if on_balance_update:
            self.state_manager.on_balance_update(on_balance_update)
        
        if on_transaction_update:
            self.state_manager.on_transaction_update(on_transaction_update)
        
        def get_blockchain_data(addresses):
            try:
                return self.blockchain.scan_transactions_for_addresses(addresses)
            except Exception as e:
                print(f"⚠️  Blockchain scan error: {e}")
                return {}
        
        def get_mempool_data(addresses):
            try:
                return self.mempool.get_pending_transactions_for_addresses(addresses)
            except Exception as e:
                print(f"⚠️  Mempool fetch error: {e}")
                return {}
        
        self.state_manager.sync_wallets_background(
            get_blockchain_data,
            get_mempool_data,
            poll_interval
        )
    
    def get_wallet_balance(self, address: str) -> Optional[Dict]:
        """Get current balance for a wallet"""
        return self.state_manager.get_balance(address)
    
    def get_wallet_transactions(self, address: str, tx_type: str = 'all') -> List[Dict]:
        """Get transactions for a wallet"""
        return self.state_manager.get_transactions(address, tx_type)
    
    def get_wallet_summary(self, address: str) -> Optional[Dict]:
        """Get complete summary for a wallet"""
        return self.state_manager.get_wallet_summary(address)
    
    def get_all_wallets_summary(self) -> Dict:
        """Get summaries for all wallets"""
        return self.state_manager.get_all_summaries()


# Convenience function to create sync helper
def create_wallet_sync_helper(wallet=None, blockchain=None, mempool=None) -> WalletSyncHelper:
    """Create a new WalletSyncHelper instance"""
    return WalletSyncHelper(wallet, blockchain, mempool)
