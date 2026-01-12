# Unified Wallet System Documentation

## Overview

The unified wallet system provides a comprehensive solution for managing multiple wallets with real-time balance tracking, transaction history, and efficient blockchain scanning. It supports:

- ✅ Multiple wallet management
- ✅ Real-time balance updates (available, pending, total)
- ✅ Transaction categorization (transfers, rewards, genesis)
- ✅ Pending transaction tracking from mempool
- ✅ Single blockchain scan for all wallets
- ✅ Real-time UI updates via callbacks
- ✅ Background synchronization

## Architecture

### Components

1. **WalletStateManager** (`lunalib/wallet_manager.py`)
   - Central state management for all wallets
   - Efficient transaction processing and categorization
   - Real-time balance calculations
   - Callback system for UI updates

2. **WalletSyncHelper** (`lunalib/wallet_sync_helper.py`)
   - Bridges LunaWallet, BlockchainManager, and MempoolManager
   - Handles data flow and integration
   - Manages continuous synchronization

3. **LunaWallet** (enhanced `lunalib/core/wallet.py`)
   - New integration methods
   - Simplified API for the unified system
   - Real-time synchronization support

## Usage

### Basic Setup

```python
from lunalib.core.wallet import LunaWallet
from lunalib.core.blockchain import BlockchainManager
from lunalib.core.mempool import MempoolManager

# Initialize components
wallet = LunaWallet()
blockchain = BlockchainManager()
mempool = MempoolManager()

# Create wallets
wallet.create_wallet("My Wallet 1", "password123")
wallet.create_new_wallet("My Wallet 2", "password456")

# Unlock wallets for use
wallet.unlock_wallet(wallet.current_wallet_address, "password123")
```

### Single Sync (One-Time)

Perform a single synchronization to get current balances and transactions:

```python
# Sync all wallets once
summaries = wallet.sync_with_state_manager(blockchain, mempool)

# Get detailed info for current wallet
details = wallet.get_wallet_details()
print(f"Balance: {details['balance']['confirmed_balance']}")
print(f"Available: {details['balance']['available_balance']}")
print(f"Pending Incoming: {details['balance']['pending_incoming']}")
print(f"Pending Outgoing: {details['balance']['pending_outgoing']}")

# Get transactions
transactions = wallet.get_wallet_transactions(tx_type='confirmed')
for tx in transactions:
    print(f"  {tx['type']} - {tx['amount']} LUN - {tx['direction']}")
```

### Continuous Sync (Real-Time Updates)

Start background synchronization that updates every 30 seconds:

```python
# Start continuous sync with automatic balance updates
wallet.start_continuous_sync(blockchain, mempool, poll_interval=30)

# Register UI callback for balance updates
def on_balance_update(balance_data):
    for address, balance in balance_data.items():
        print(f"{address}: {balance['available_balance']} LUN available")

wallet.register_wallet_ui_callback(on_balance_update)
```

### Getting Transaction Data

```python
# Get all transaction types
all_txs = wallet.get_wallet_transactions(tx_type='all')

# Get only confirmed transactions
confirmed = wallet.get_wallet_transactions(tx_type='confirmed')

# Get only pending transactions
pending = wallet.get_wallet_transactions(tx_type='pending')

# Get only transfers
transfers = wallet.get_wallet_transactions(tx_type='transfers')

# Get only rewards
rewards = wallet.get_wallet_transactions(tx_type='rewards')

# Get genesis transactions
genesis = wallet.get_wallet_transactions(tx_type='genesis')

# Get for specific address
other_wallet_txs = wallet.get_wallet_transactions(
    address="LUN_OTHER_ADDRESS",
    tx_type='all'
)
```

## Data Structures

### Balance Information

```python
{
    'confirmed_balance': 1000.5,      # Total confirmed transactions
    'available_balance': 900.0,        # Can spend (minus pending outgoing)
    'pending_incoming': 100.0,         # Incoming pending from mempool
    'pending_outgoing': 200.5,         # Outgoing pending + fees
    'total_balance': 1100.5            # confirmed + pending incoming
}
```

### Transaction Object

```python
{
    'hash': 'abc123def...',
    'type': 'transfer',                # transfer, reward, gtx_genesis
    'from_address': 'LUN_SENDER...',
    'to_address': 'LUN_RECEIVER...',
    'amount': 100.5,
    'fee': 0.001,
    'timestamp': 1703424000,
    'status': 'confirmed',             # confirmed or pending
    'block_height': 12345,             # Only for confirmed
    'confirmations': 10,               # Only for confirmed
    'memo': 'Payment for service',
    'direction': 'outgoing'            # incoming, outgoing, or ''
}
```

### Wallet Summary

```python
wallet_details = wallet.get_wallet_details(address)
# Returns:
{
    'address': 'LUN_...',
    'balance': {
        'confirmed_balance': 1000.0,
        'available_balance': 900.0,
        'pending_incoming': 0.0,
        'pending_outgoing': 100.0,
        'total_balance': 1000.0
    },
    'transaction_counts': {
        'confirmed': 25,
        'pending': 3,
        'transfers_confirmed': 20,
        'transfers_pending': 2,
        'rewards': 5,
        'genesis': 0
    },
    'transactions': {
        'confirmed': [...],            # Last 10
        'pending': [...],
        'rewards': [...]
    },
    'last_updated': 1703424120.5
}
```

## Advanced Usage

### Using WalletStateManager Directly

```python
from lunalib.wallet_manager import get_wallet_manager

state_manager = get_wallet_manager()

# Register wallets
state_manager.register_wallets([
    "LUN_ADDRESS1",
    "LUN_ADDRESS2",
    "LUN_ADDRESS3"
])

# Get data from blockchain and mempool
blockchain_txs = blockchain.scan_transactions_for_addresses(addresses)
mempool_txs = mempool.get_pending_transactions_for_addresses(addresses)

# Sync with raw data
state_manager.sync_wallets_from_sources(blockchain_txs, mempool_txs)

# Query results
balance = state_manager.get_balance("LUN_ADDRESS1")
all_txs = state_manager.get_transactions("LUN_ADDRESS1", 'all')
summary = state_manager.get_wallet_summary("LUN_ADDRESS1")
```

### Custom Callbacks

```python
from lunalib.wallet_manager import get_wallet_manager

state_manager = get_wallet_manager()

def handle_balance_update(balance_data):
    """Called whenever balances change"""
    for address, balance in balance_data.items():
        if balance['pending_outgoing'] > 0:
            print(f"⏳ {address} has pending transactions")

def handle_transaction_update(transaction_data):
    """Called whenever transactions change"""
    for address, txs in transaction_data.items():
        if txs['pending']:
            print(f"📤 {address} has {len(txs['pending'])} pending txs")

state_manager.on_balance_update(handle_balance_update)
state_manager.on_transaction_update(handle_transaction_update)
```

### Background Monitoring

```python
# Start continuous sync with callbacks
def on_balance_change(balances):
    print(f"Balances updated: {balances}")

def on_tx_change(transactions):
    print(f"Transactions updated: {transactions}")

wallet.register_wallet_ui_callback(on_balance_change)
wallet.start_continuous_sync(blockchain, mempool, poll_interval=30)
```

## Performance Characteristics

### Single Blockchain Scan
- Scans blockchain once regardless of number of wallets
- Returns transactions for all registered addresses in one pass
- Efficient batching of block retrieval (100 blocks per batch)

### Memory Efficiency
- Caches processed transaction hashes to avoid duplicates
- Maintains transaction categorization efficiently
- Thread-safe operations with minimal locking

### Real-Time Updates
- Balance updates available immediately after sync
- Callbacks triggered for UI responsiveness
- Background thread doesn't block main application

## Transaction Categorization

Transactions are automatically categorized by type:

### Confirmed Transfers
- Type: `transfer` with status `confirmed`
- Counted in confirmed balance calculations
- Have block height and confirmation count

### Pending Transfers
- Type: `transfer` with status `pending`
- Reduce available balance
- From mempool, not yet confirmed

### Rewards
- Type: `reward` with automatic detection
- Always counted as incoming
- Can be confirmed or pending

### Genesis Transactions
- Type: `gtx_genesis`
- Initial digital bill distributions
- Track genesis money flow

## Error Handling

The system includes comprehensive error handling:

```python
# Sync errors are caught and logged
summaries = wallet.sync_with_state_manager(blockchain, mempool)
if not summaries:
    print("Sync failed - check logs for details")

# Missing data returns empty collections
transactions = wallet.get_wallet_transactions(address="INVALID_ADDRESS")
# Returns: []

# Balance queries on non-existent wallets
details = wallet.get_wallet_details("INVALID_ADDRESS")
# Returns: None
```

## Best Practices

1. **Initial Sync**: Always sync once before displaying wallet data
   ```python
   wallet.sync_with_state_manager(blockchain, mempool)
   ```

2. **Real-Time Updates**: Use continuous sync for responsive UI
   ```python
   wallet.start_continuous_sync(blockchain, mempool, poll_interval=30)
   wallet.register_wallet_ui_callback(update_ui_function)
   ```

3. **Balance Checks**: Always use `available_balance` when checking if user can spend
   ```python
   details = wallet.get_wallet_details()
   can_spend = amount <= details['balance']['available_balance']
   ```

4. **Transaction Monitoring**: Check pending transactions for UX
   ```python
   pending = wallet.get_wallet_transactions(tx_type='pending')
   if pending:
       show_spinner()  # Show transaction is processing
   ```

5. **Error Handling**: Always check for None/empty results
   ```python
   details = wallet.get_wallet_details()
   if not details:
       handle_wallet_error()
   ```

## Troubleshooting

### Balances Not Updating
1. Check blockchain connectivity: `blockchain.check_network_connection()`
2. Verify wallet addresses are registered: `wallet.wallets.keys()`
3. Check mempool has data: `mempool.get_mempool()`

### Missing Transactions
1. Ensure sync was performed: `wallet.sync_with_state_manager(...)`
2. Check transaction type: transactions are categorized by type
3. Verify address format: addresses must be normalized (lowercase)

### Performance Issues
1. Reduce poll interval for continuous sync (at cost of more network traffic)
2. Use filters for transaction queries: `tx_type='pending'` instead of `'all'`
3. Monitor memory usage of transaction caches

## Examples

### Complete Wallet Application Flow

```python
from lunalib.core.wallet import LunaWallet
from lunalib.core.blockchain import BlockchainManager
from lunalib.core.mempool import MempoolManager

# Initialize
wallet = LunaWallet()
blockchain = BlockchainManager()
mempool = MempoolManager()

# Create and unlock wallet
wallet.create_wallet("Main", "pass123")
wallet.unlock_wallet(wallet.current_wallet_address, "pass123")

# Initial sync
summaries = wallet.sync_with_state_manager(blockchain, mempool)

# Display balance
details = wallet.get_wallet_details()
print(f"Available: {details['balance']['available_balance']} LUN")

# Start continuous updates
def ui_update(balances):
    for addr, bal in balances.items():
        if addr == wallet.current_wallet_address:
            # Update UI with new balance
            update_balance_display(bal['available_balance'])

wallet.register_wallet_ui_callback(ui_update)
wallet.start_continuous_sync(blockchain, mempool, poll_interval=30)

# Send transaction
wallet.send_transaction(to_address="LUN_RECEIVER", amount=100.0)

# Get updated transactions
pending = wallet.get_wallet_transactions(tx_type='pending')
print(f"Pending: {len(pending)} transactions")

# Wait for confirmation (happens automatically via background sync)
```

## API Reference

### LunaWallet Methods

- `sync_with_state_manager(blockchain, mempool)` → Dict
- `get_wallet_details(address=None)` → Dict | None
- `get_wallet_transactions(address=None, tx_type='all')` → List[Dict]
- `register_wallet_ui_callback(callback)` → None
- `start_continuous_sync(blockchain, mempool, poll_interval=30)` → None

### WalletStateManager Methods

- `register_wallet(address)` → WalletState
- `register_wallets(addresses)` → Dict[str, WalletState]
- `sync_wallets_from_sources(blockchain_txs, mempool_txs)` → None
- `sync_wallets_background(get_blockchain, get_mempool, interval)` → None
- `get_balance(address)` → Dict | None
- `get_all_balances()` → Dict[str, Dict]
- `get_transactions(address, type)` → List[Dict]
- `get_wallet_summary(address)` → Dict | None
- `get_all_summaries()` → Dict[str, Dict]
- `on_balance_update(callback)` → None
- `on_transaction_update(callback)` → None
