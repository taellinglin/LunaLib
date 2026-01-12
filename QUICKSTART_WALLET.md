# Quick Start Guide - Unified Wallet System

## 5-Minute Setup

### 1. Import What You Need

```python
from lunalib.core.wallet import LunaWallet
from lunalib.core.blockchain import BlockchainManager
from lunalib.core.mempool import MempoolManager
```

### 2. Initialize Components

```python
wallet = LunaWallet()
blockchain = BlockchainManager()
mempool = MempoolManager()
```

### 3. Create a Wallet

```python
wallet.create_wallet("My Wallet", "mypassword")
wallet.unlock_wallet(wallet.current_wallet_address, "mypassword")
```

### 4. Get Current Balance

```python
# One-time sync
wallet.sync_with_state_manager(blockchain, mempool)

# Get balance
details = wallet.get_wallet_details()
print(f"Available: {details['balance']['available_balance']} LUN")
```

## Common Tasks

### Get Balance (Single Call)

```python
details = wallet.get_wallet_details()
print(details['balance']['available_balance'])
```

### Get All Transactions

```python
transactions = wallet.get_wallet_transactions(tx_type='all')
for tx in transactions:
    print(f"{tx['type']}: {tx['amount']} LUN - {tx['status']}")
```

### Get Pending Transactions

```python
pending = wallet.get_wallet_transactions(tx_type='pending')
print(f"Pending: {len(pending)} transactions")
```

### Get Confirmed Transfers Only

```python
transfers = wallet.get_wallet_transactions(tx_type='transfers')
for tx in transfers:
    if tx['status'] == 'confirmed':
        print(f"Transfer: {tx['amount']} LUN")
```

### Get Rewards

```python
rewards = wallet.get_wallet_transactions(tx_type='rewards')
print(f"Total rewards: {sum(tx['amount'] for tx in rewards)} LUN")
```

### Manage Multiple Wallets

```python
# Create multiple
wallet.create_wallet("Wallet 1", "pass1")
wallet.create_new_wallet("Wallet 2", "pass2")

# Sync all at once
wallet.sync_with_state_manager(blockchain, mempool)

# Check specific wallet
wallet.switch_wallet("LUN_ADDRESS_1", "pass1")
details = wallet.get_wallet_details()
```

### Live Balance Updates

```python
# Register callback
def on_balance_update(balances):
    for addr, bal in balances.items():
        print(f"Available: {bal['available_balance']} LUN")

wallet.register_wallet_ui_callback(on_balance_update)

# Start continuous sync
wallet.start_continuous_sync(blockchain, mempool, poll_interval=30)

# Callback will be called every 30 seconds or when balance changes
```

### Check Pending Outgoing

```python
details = wallet.get_wallet_details()
if details['balance']['pending_outgoing'] > 0:
    print("You have pending transactions")
```

### Send Transaction

```python
# Balance is automatically updated
success = wallet.send_transaction(
    to_address="LUN_RECEIVER_ADDRESS",
    amount=100.0,
    memo="Payment"
)

if success:
    print("Transaction sent!")
    # Get updated balance
    details = wallet.get_wallet_details()
    print(f"Available now: {details['balance']['available_balance']}")
```

## Data Structure Quick Reference

### Balance Info
```python
balance = details['balance']
balance['confirmed_balance']      # Already confirmed
balance['available_balance']      # Can spend now
balance['pending_incoming']       # Money coming in
balance['pending_outgoing']       # Money going out + fees
balance['total_balance']          # confirmed + pending incoming
```

### Transaction Info
```python
tx = transaction_list[0]
tx['hash']          # Transaction ID
tx['type']          # 'transfer', 'reward', 'gtx_genesis'
tx['amount']        # LUN amount
tx['fee']           # Transaction fee
tx['status']        # 'confirmed' or 'pending'
tx['direction']     # 'incoming', 'outgoing', or ''
tx['timestamp']     # Unix timestamp
tx['block_height']  # Block number (confirmed only)
```

## Transaction Types

- **`'all'`** - All transactions
- **`'confirmed'`** - Only confirmed transactions
- **`'pending'`** - Only pending (mempool) transactions
- **`'transfers'`** - Send/receive transactions
- **`'rewards'`** - Block rewards
- **`'genesis'`** - Genesis transactions

## Complete Minimal Example

```python
from lunalib.core.wallet import LunaWallet
from lunalib.core.blockchain import BlockchainManager
from lunalib.core.mempool import MempoolManager

# Setup
wallet = LunaWallet()
blockchain = BlockchainManager()
mempool = MempoolManager()

# Create wallet
wallet.create_wallet("Test", "pass123")
wallet.unlock_wallet(wallet.current_wallet_address, "pass123")

# Get balance
wallet.sync_with_state_manager(blockchain, mempool)
details = wallet.get_wallet_details()
print(f"Balance: {details['balance']['available_balance']} LUN")

# Get transactions
txs = wallet.get_wallet_transactions(tx_type='all')
print(f"Transactions: {len(txs)}")

# Real-time updates
def update(balances):
    print(f"Updated: {balances}")

wallet.register_wallet_ui_callback(update)
wallet.start_continuous_sync(blockchain, mempool, poll_interval=30)
```

## Performance Tips

1. **Call `sync_with_state_manager()` once** at startup
2. **Use `start_continuous_sync()`** for real-time updates instead of polling manually
3. **Filter by transaction type** instead of getting all transactions
4. **Check `available_balance`** before sending (not total balance)
5. **Monitor `pending_outgoing`** to show blocked funds

## Troubleshooting

### Balances are zero?
→ Make sure you called `wallet.sync_with_state_manager()` after creating wallet

### Transactions not showing?
→ Check the address is correct and has activity on blockchain

### Real-time updates not working?
→ Verify `start_continuous_sync()` was called and blockchain/mempool have network access

### Getting old balance?
→ If using continuous sync, callback is called automatically - just use data from callback

## What's New vs. Old System?

| Feature | Old | New |
|---------|-----|-----|
| Single scan for multiple wallets | ❌ | ✅ |
| Automatic transaction categorization | ❌ | ✅ |
| Real-time balance updates | ❌ | ✅ |
| Pending transaction tracking | ❌ | ✅ |
| Available vs confirmed balance | ⚠️ | ✅ |
| UI callbacks for updates | ❌ | ✅ |
| Transaction history by type | ❌ | ✅ |

## Next Steps

1. Read [WALLET_SYSTEM_GUIDE.md](WALLET_SYSTEM_GUIDE.md) for comprehensive documentation
2. Check [examples_wallet_system.py](examples_wallet_system.py) for practical examples
3. See [lunalib/wallet_manager.py](lunalib/wallet_manager.py) for implementation details
