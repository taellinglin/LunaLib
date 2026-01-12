"""
Practical Examples - Unified Wallet System

This file demonstrates real-world usage patterns for the unified wallet system.
"""

# ============================================================================
# Example 1: Basic Single-Wallet Balance Checking
# ============================================================================

def example_check_balance():
    """Get current balance for a single wallet"""
    from lunalib.core.wallet import LunaWallet
    from lunalib.core.blockchain import BlockchainManager
    from lunalib.core.mempool import MempoolManager
    
    # Initialize
    wallet = LunaWallet()
    blockchain = BlockchainManager()
    mempool = MempoolManager()
    
    # Create wallet
    wallet.create_wallet("My Main Wallet", "password123")
    wallet.unlock_wallet(wallet.current_wallet_address, "password123")
    
    # Sync once to get current state
    wallet.sync_with_state_manager(blockchain, mempool)
    
    # Get balance
    details = wallet.get_wallet_details()
    
    if details:
        bal = details['balance']
        print(f"💰 Wallet Balance")
        print(f"   Total Confirmed: {bal['confirmed_balance']:.2f} LUN")
        print(f"   Available: {bal['available_balance']:.2f} LUN")
        print(f"   Pending Incoming: {bal['pending_incoming']:.2f} LUN")
        print(f"   Pending Outgoing: {bal['pending_outgoing']:.2f} LUN")


# ============================================================================
# Example 2: Multiple Wallet Management
# ============================================================================

def example_multiple_wallets():
    """Manage and sync multiple wallets"""
    from lunalib.core.wallet import LunaWallet
    from lunalib.core.blockchain import BlockchainManager
    from lunalib.core.mempool import MempoolManager
    
    # Initialize
    wallet = LunaWallet()
    blockchain = BlockchainManager()
    mempool = MempoolManager()
    
    # Create multiple wallets
    wallet.create_wallet("Main Wallet", "pass1")
    main_address = wallet.current_wallet_address
    
    wallet.create_new_wallet("Savings", "pass2")
    wallet.create_new_wallet("Trading", "pass3")
    
    # Sync all at once
    summaries = wallet.sync_with_state_manager(blockchain, mempool)
    
    # Display all wallet balances
    print("📱 All Wallets:")
    for address, summary in summaries.items():
        label = wallet.wallets[address].get('label', 'Unknown')
        bal = summary['balance']
        print(f"  {label}:")
        print(f"    Available: {bal['available_balance']:.2f} LUN")
        print(f"    Total: {bal['confirmed_balance']:.2f} LUN")


# ============================================================================
# Example 3: Real-Time Balance Updates with UI Callback
# ============================================================================

def example_real_time_updates():
    """Update UI with real-time balance changes"""
    from lunalib.core.wallet import LunaWallet
    from lunalib.core.blockchain import BlockchainManager
    from lunalib.core.mempool import MempoolManager
    import time
    
    # Initialize
    wallet = LunaWallet()
    blockchain = BlockchainManager()
    mempool = MempoolManager()
    
    wallet.create_wallet("Live Wallet", "password123")
    wallet.unlock_wallet(wallet.current_wallet_address, "password123")
    
    # Define UI update callback
    def update_ui_balance(balance_data):
        """This gets called whenever balances change"""
        for address, balance in balance_data.items():
            if address == wallet.current_wallet_address:
                # Update UI elements here
                print(f"💹 Balance Updated: {balance['available_balance']:.2f} LUN available")
                
                if balance['pending_outgoing'] > 0:
                    print(f"   ⏳ Pending outgoing: {balance['pending_outgoing']:.2f} LUN")
    
    # Register callback
    wallet.register_wallet_ui_callback(update_ui_balance)
    
    # Initial sync
    wallet.sync_with_state_manager(blockchain, mempool)
    
    # Start continuous sync (checks every 30 seconds)
    wallet.start_continuous_sync(blockchain, mempool, poll_interval=30)
    
    print("✅ Real-time balance updates started (will run in background)")
    print("   Callback will be triggered whenever balance changes")
    
    # Application continues running, callback is called automatically
    # In real app, this would be event loop or web framework
    time.sleep(120)  # Run for 2 minutes


# ============================================================================
# Example 4: Transaction History Display
# ============================================================================

def example_transaction_history():
    """Display transaction history with categorization"""
    from lunalib.core.wallet import LunaWallet
    from lunalib.core.blockchain import BlockchainManager
    from lunalib.core.mempool import MempoolManager
    from datetime import datetime
    
    # Initialize
    wallet = LunaWallet()
    blockchain = BlockchainManager()
    mempool = MempoolManager()
    
    wallet.create_wallet("History Wallet", "password123")
    wallet.unlock_wallet(wallet.current_wallet_address, "password123")
    
    # Sync
    wallet.sync_with_state_manager(blockchain, mempool)
    
    # Get all transactions
    all_txs = wallet.get_wallet_transactions(tx_type='all')
    
    print(f"📋 Transaction History ({len(all_txs)} total)")
    print("-" * 70)
    
    for tx in all_txs[:10]:  # Show last 10
        timestamp = datetime.fromtimestamp(tx['timestamp']).strftime('%Y-%m-%d %H:%M')
        direction = "→" if tx['direction'] == 'outgoing' else "←"
        status_icon = "✓" if tx['status'] == 'confirmed' else "⏳"
        
        print(f"{status_icon} {timestamp} {direction} {tx['type'].upper():12} "
              f"{tx['amount']:10.2f} LUN")
    
    # Get specific transaction types
    rewards = wallet.get_wallet_transactions(tx_type='rewards')
    pending = wallet.get_wallet_transactions(tx_type='pending')
    
    print(f"\n💎 Rewards: {len(rewards)} total")
    print(f"⏳ Pending Transactions: {len(pending)}")


# ============================================================================
# Example 5: Monitor for Incoming Payments
# ============================================================================

def example_monitor_incoming():
    """Monitor wallet for incoming transactions"""
    from lunalib.core.wallet import LunaWallet
    from lunalib.core.blockchain import BlockchainManager
    from lunalib.core.mempool import MempoolManager
    
    # Initialize
    wallet = LunaWallet()
    blockchain = BlockchainManager()
    mempool = MempoolManager()
    
    wallet.create_wallet("Store Wallet", "password123")
    wallet.unlock_wallet(wallet.current_wallet_address, "password123")
    
    # Track incoming transactions
    last_confirmed_count = 0
    
    def check_for_payments(balance_data):
        """Alert when new payments arrive"""
        nonlocal last_confirmed_count
        
        for address, balance in balance_data.items():
            if address == wallet.current_wallet_address:
                # Check for pending incoming
                if balance['pending_incoming'] > 0:
                    print(f"💰 INCOMING PAYMENT PENDING: {balance['pending_incoming']:.2f} LUN")
    
    wallet.register_wallet_ui_callback(check_for_payments)
    
    # Initial sync
    wallet.sync_with_state_manager(blockchain, mempool)
    
    # Start monitoring
    wallet.start_continuous_sync(blockchain, mempool, poll_interval=10)
    
    print("✅ Payment monitor active - will alert on incoming transactions")


# ============================================================================
# Example 6: Balance-Based Decision Making
# ============================================================================

def example_conditional_logic():
    """Use balance information to make decisions"""
    from lunalib.core.wallet import LunaWallet
    from lunalib.core.blockchain import BlockchainManager
    from lunalib.core.mempool import MempoolManager
    
    # Initialize
    wallet = LunaWallet()
    blockchain = BlockchainManager()
    mempool = MempoolManager()
    
    wallet.create_wallet("Trading Wallet", "password123")
    wallet.unlock_wallet(wallet.current_wallet_address, "password123")
    
    # Sync
    wallet.sync_with_state_manager(blockchain, mempool)
    
    details = wallet.get_wallet_details()
    bal = details['balance']
    
    # Decision logic
    TRANSACTION_THRESHOLD = 100.0
    
    if bal['available_balance'] < TRANSACTION_THRESHOLD:
        print("⚠️  Insufficient balance for transaction")
    else:
        print(f"✅ Can proceed with transaction ({bal['available_balance']:.2f} available)")
    
    # Check for blocked funds
    if bal['pending_outgoing'] > 0:
        print(f"⏳ {bal['pending_outgoing']:.2f} LUN is pending")
        print(f"   Available balance will be reduced when confirmed")
    
    # Monitor pending
    pending_txs = wallet.get_wallet_transactions(tx_type='pending')
    if pending_txs:
        print(f"⏳ Waiting for {len(pending_txs)} transaction(s) to confirm...")
        for tx in pending_txs:
            print(f"   - {tx['type']}: {tx['amount']} LUN")


# ============================================================================
# Example 7: Comprehensive Wallet Summary Display
# ============================================================================

def example_wallet_dashboard():
    """Display comprehensive wallet information dashboard"""
    from lunalib.core.wallet import LunaWallet
    from lunalib.core.blockchain import BlockchainManager
    from lunalib.core.mempool import MempoolManager
    
    # Initialize
    wallet = LunaWallet()
    blockchain = BlockchainManager()
    mempool = MempoolManager()
    
    # Create demo wallets
    wallet.create_wallet("Dashboard Wallet", "password123")
    wallet.unlock_wallet(wallet.current_wallet_address, "password123")
    
    # Sync
    wallet.sync_with_state_manager(blockchain, mempool)
    
    # Get summary
    summary = wallet.get_wallet_summary()
    
    if not summary:
        print("No wallet data available")
        return
    
    # Display dashboard
    print("=" * 70)
    print(f"💼 WALLET DASHBOARD - {summary['address']}")
    print("=" * 70)
    
    bal = summary['balance']
    
    # Balance Section
    print("\n💰 BALANCE SUMMARY")
    print(f"   Confirmed:        {bal['confirmed_balance']:12.2f} LUN")
    print(f"   Available:        {bal['available_balance']:12.2f} LUN ✓")
    print(f"   Pending Incoming: {bal['pending_incoming']:12.2f} LUN ↓")
    print(f"   Pending Outgoing: {bal['pending_outgoing']:12.2f} LUN ↑")
    
    # Transaction Counts
    print("\n📊 TRANSACTION COUNTS")
    counts = summary['transaction_counts']
    print(f"   Confirmed:   {counts['confirmed']:5} transactions")
    print(f"   Pending:     {counts['pending']:5} transactions")
    print(f"   Transfers:   {counts['transfers_confirmed']:5} confirmed, "
          f"{counts['transfers_pending']:5} pending")
    print(f"   Rewards:     {counts['rewards']:5} total")
    print(f"   Genesis:     {counts['genesis']:5} total")
    
    # Recent Transactions
    if summary['transactions']['confirmed']:
        print("\n📝 RECENT CONFIRMED TRANSACTIONS")
        for tx in summary['transactions']['confirmed'][:3]:
            print(f"   • {tx['type']:10} {tx['amount']:8.2f} LUN "
                  f"({'→' if tx['direction'] == 'outgoing' else '←'})")
    
    if summary['transactions']['pending']:
        print("\n⏳ PENDING TRANSACTIONS")
        for tx in summary['transactions']['pending']:
            print(f"   • {tx['type']:10} {tx['amount']:8.2f} LUN "
                  f"({'→' if tx['direction'] == 'outgoing' else '←'})")
    
    print("\n" + "=" * 70)


# ============================================================================
# Example 8: Bulk Operations on Multiple Wallets
# ============================================================================

def example_bulk_operations():
    """Perform operations on multiple wallets efficiently"""
    from lunalib.core.wallet import LunaWallet
    from lunalib.core.blockchain import BlockchainManager
    from lunalib.core.mempool import MempoolManager
    
    # Initialize
    wallet = LunaWallet()
    blockchain = BlockchainManager()
    mempool = MempoolManager()
    
    # Create multiple wallets
    addresses = []
    for i in range(1, 4):
        wallet.create_new_wallet(f"Wallet {i}", f"pass{i}")
        addresses.append(wallet.current_wallet_address)
    
    # Sync all at once (single blockchain scan)
    print(f"🔄 Syncing {len(addresses)} wallets...")
    summaries = wallet.sync_with_state_manager(blockchain, mempool)
    
    # Process results
    total_available = 0
    total_pending = 0
    
    for address, summary in summaries.items():
        bal = summary['balance']
        total_available += bal['available_balance']
        total_pending += bal['pending_outgoing']
        
        label = wallet.wallets[address].get('label', 'Unknown')
        print(f"✓ {label:20} {bal['available_balance']:10.2f} LUN available")
    
    print(f"\n📊 TOTAL ACROSS ALL WALLETS")
    print(f"   Available to Spend: {total_available:.2f} LUN")
    print(f"   Pending Outgoing:   {total_pending:.2f} LUN")


# ============================================================================
# Run Examples
# ============================================================================

if __name__ == "__main__":
    print("Unified Wallet System - Practical Examples\n")
    
    examples = [
        ("1. Check Single Wallet Balance", example_check_balance),
        ("2. Manage Multiple Wallets", example_multiple_wallets),
        ("3. Real-Time Updates", example_real_time_updates),
        ("4. Transaction History", example_transaction_history),
        ("5. Monitor Incoming Payments", example_monitor_incoming),
        ("6. Balance-Based Decisions", example_conditional_logic),
        ("7. Wallet Dashboard", example_wallet_dashboard),
        ("8. Bulk Operations", example_bulk_operations),
    ]
    
    print("Available Examples:")
    for name, _ in examples:
        print(f"  {name}")
    
    # Uncomment to run specific example
    # example_check_balance()
