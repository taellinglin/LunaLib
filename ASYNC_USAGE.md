# LunaLib Async/Threading Usage Guide

## Overview

LunaLib now supports async/threaded operations to prevent blocking your web interface or daemon. All blockchain scanning, transaction broadcasting, and block submission operations can run in background threads.

## Key Features

✅ **Non-blocking operations** - All heavy operations run in background threads
✅ **Task tracking** - Monitor progress of async operations
✅ **Callbacks** - Get notified when operations complete
✅ **Thread pooling** - Efficient resource management with configurable worker pools

---

## BlockchainManager Async Methods

### 1. Async Transaction Scanning

#### Single Address Scanning
```python
from lunalib.core.blockchain import BlockchainManager

blockchain = BlockchainManager("https://bank.linglin.art", max_workers=10)

# Define callback for when scan completes
def on_scan_complete(success, result, error):
    if success:
        print(f"Found {len(result)} transactions!")
        for tx in result:
            print(f"  - {tx['hash'][:16]}... Amount: {tx['amount']}")
    else:
        print(f"Scan failed: {error}")

# Start async scan (returns immediately)
task_id = blockchain.scan_transactions_for_address_async(
    address="LUN_abc123...",
    callback=on_scan_complete,
    start_height=0,
    end_height=1000
)

print(f"Scan started with task ID: {task_id}")
# Your web interface continues working...

# Check task status later
status = blockchain.get_task_status(task_id)
print(f"Task status: {status['status']}")  # 'running', 'completed', 'failed'
```

#### Multiple Address Scanning
```python
# Scan multiple addresses at once (more efficient)
addresses = ["LUN_addr1", "LUN_addr2", "LUN_addr3"]

def on_multi_scan_complete(success, result, error):
    if success:
        for addr, txs in result.items():
            print(f"{addr}: {len(txs)} transactions")

task_id = blockchain.scan_transactions_for_addresses_async(
    addresses=addresses,
    callback=on_multi_scan_complete,
    start_height=0
)
```

### 2. Async Block Operations

#### Get Block Range
```python
def on_blocks_fetched(success, result, error):
    if success:
        print(f"Fetched {len(result)} blocks")
        for block in result:
            print(f"  Block #{block['index']}: {block['hash'][:16]}...")

task_id = blockchain.get_blocks_range_async(
    start_height=100,
    end_height=200,
    callback=on_blocks_fetched
)
```

### 3. Async Transaction Broadcasting

```python
def on_broadcast_complete(success, result, error):
    if success:
        print(f"Transaction broadcast successful: {result}")
    else:
        print(f"Broadcast failed: {error}")

transaction = {
    'type': 'transaction',
    'from': 'LUN_sender',
    'to': 'LUN_receiver',
    'amount': 10.5,
    'timestamp': time.time(),
    'hash': '...',
    'signature': '...'
}

task_id = blockchain.broadcast_transaction_async(
    transaction=transaction,
    callback=on_broadcast_complete
)
```

### 4. Async Block Submission

```python
def on_block_submitted(success, result, error):
    if success:
        print(f"Block #{result['index']} submitted successfully!")
    else:
        print(f"Block submission failed: {error}")

task_id = blockchain.submit_mined_block_async(
    block_data=mined_block,
    callback=on_block_submitted
)
```

---

## BlockchainDaemon Async Methods

### 1. Async Block Validation

```python
from lunalib.core.daemon import BlockchainDaemon

daemon = BlockchainDaemon(blockchain_manager, mempool_manager, max_workers=5)
daemon.start()

def on_validation_complete(success, result, error):
    if success:
        print(f"Block is valid: {result['message']}")
    else:
        print(f"Block validation failed: {error}")

task_id = daemon.validate_block_async(
    block=incoming_block,
    callback=on_validation_complete
)
```

### 2. Async Block Processing

```python
def on_block_processed(success, result, error):
    if success:
        print(f"Block processed and propagated to peers")
    else:
        print(f"Block processing failed: {error}")

task_id = daemon.process_incoming_block_async(
    block=incoming_block,
    from_peer="peer_node_123",
    callback=on_block_processed
)
```

---

## Task Management

### Check Task Status
```python
# Check if task is still running
status = blockchain.get_task_status(task_id)

if status['status'] == 'running':
    print("Task still running...")
elif status['status'] == 'completed':
    print(f"Task completed! Result: {status['result']}")
elif status['status'] == 'failed':
    print(f"Task failed: {status['error']}")
elif status['status'] == 'not_found':
    print("Task not found (may have been cleaned up)")
```

### Cancel Running Tasks
```python
# Cancel a long-running task
if blockchain.cancel_task(task_id):
    print(f"Task {task_id} cancelled")
else:
    print("Could not cancel task (may have already completed)")
```

### List Active Tasks
```python
# Get all currently running tasks
active_tasks = blockchain.get_active_tasks()
print(f"Active tasks: {active_tasks}")

# Also check daemon
daemon_tasks = daemon.get_active_tasks()
print(f"Daemon active tasks: {daemon_tasks}")
```

### Cleanup Completed Tasks
```python
# Periodically clean up completed tasks to free memory
blockchain.cleanup_completed_tasks()
daemon.cleanup_completed_tasks()
```

---

## Flask/Web Integration Example

```python
from flask import Flask, jsonify, request
from lunalib.core.blockchain import BlockchainManager

app = Flask(__name__)
blockchain = BlockchainManager("https://bank.linglin.art", max_workers=20)

# Track tasks in memory (or use Redis/database for production)
active_scans = {}

@app.route('/api/scan/<address>', methods=['POST'])
def scan_address(address):
    """Start async scan and return task ID immediately"""
    
    def on_complete(success, result, error):
        # Store result for later retrieval
        active_scans[task_id] = {
            'success': success,
            'result': result,
            'error': error,
            'completed_at': time.time()
        }
    
    task_id = blockchain.scan_transactions_for_address_async(
        address=address,
        callback=on_complete
    )
    
    active_scans[task_id] = {'status': 'running'}
    
    return jsonify({
        'task_id': task_id,
        'message': 'Scan started'
    }), 202  # 202 Accepted

@app.route('/api/scan/status/<task_id>', methods=['GET'])
def check_scan_status(task_id):
    """Check status of a scan task"""
    
    # Check blockchain manager
    status = blockchain.get_task_status(task_id)
    
    if status['status'] == 'completed':
        # Get from our cache
        result = active_scans.get(task_id, {})
        return jsonify(result)
    
    return jsonify({
        'status': status['status'],
        'message': 'Scan in progress' if status['status'] == 'running' else 'Task not found'
    })

@app.route('/api/broadcast', methods=['POST'])
def broadcast_transaction():
    """Broadcast transaction asynchronously"""
    transaction = request.json
    
    task_id = blockchain.broadcast_transaction_async(
        transaction=transaction,
        callback=lambda success, result, error: print(f"Broadcast {'success' if success else 'failed'}")
    )
    
    return jsonify({
        'task_id': task_id,
        'message': 'Broadcasting transaction'
    }), 202

@app.route('/api/active-tasks', methods=['GET'])
def get_active_tasks():
    """Get list of all active tasks"""
    return jsonify({
        'blockchain_tasks': blockchain.get_active_tasks(),
        'daemon_tasks': daemon.get_active_tasks() if daemon else []
    })

# Cleanup task - run periodically
@app.route('/api/cleanup', methods=['POST'])
def cleanup_tasks():
    """Clean up completed tasks"""
    blockchain.cleanup_completed_tasks()
    return jsonify({'message': 'Cleanup complete'})

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
```

---

## Configuration

### Thread Pool Sizing

```python
# More workers = more parallel operations, but more memory
blockchain = BlockchainManager(
    endpoint_url="https://bank.linglin.art",
    max_workers=20  # Adjust based on your server capacity
)

daemon = BlockchainDaemon(
    blockchain_manager=blockchain,
    mempool_manager=mempool,
    max_workers=10  # Daemon usually needs fewer workers
)
```

### Shutdown Gracefully

```python
# Always shutdown cleanly when stopping your application
try:
    # Your application code
    pass
finally:
    blockchain.shutdown()  # Wait for all tasks to complete
    daemon.stop()  # Stops validation loops and executor
```

---

## Best Practices

1. **Use callbacks for UI updates** - Don't poll task status repeatedly
2. **Set reasonable max_workers** - Start with 10-20, adjust based on load
3. **Clean up completed tasks** - Run `cleanup_completed_tasks()` periodically
4. **Handle errors in callbacks** - Always check `success` parameter
5. **Use async for heavy operations** - Scanning, broadcasting, validation
6. **Keep sync for quick operations** - Getting height, checking connection
7. **Shutdown gracefully** - Call `shutdown()` before exiting

---

## Performance Tips

### Batch Operations
```python
# GOOD: Scan multiple addresses in one call
task_id = blockchain.scan_transactions_for_addresses_async(
    addresses=["addr1", "addr2", "addr3"]
)

# AVOID: Multiple separate scans
task1 = blockchain.scan_transactions_for_address_async("addr1")
task2 = blockchain.scan_transactions_for_address_async("addr2")
task3 = blockchain.scan_transactions_for_address_async("addr3")
```

### Monitor Task Queue
```python
# Check how many tasks are running
active_count = len(blockchain.get_active_tasks())
if active_count > 50:
    print("⚠️ High task load, consider increasing max_workers")
```

### Use Caching
```python
# BlockchainManager uses built-in caching
# For frequently accessed data, results are cached automatically
latest_block = blockchain.get_latest_block()  # Cached for 10 seconds
```

---

## Troubleshooting

### Tasks Stuck in "running"
```python
# Check if executor is healthy
active_tasks = blockchain.get_active_tasks()
if len(active_tasks) > 100:
    print("⚠️ Possible deadlock or too many concurrent operations")
    # Consider restarting or increasing max_workers
```

### Memory Usage High
```python
# Regular cleanup
import schedule
schedule.every(5).minutes.do(blockchain.cleanup_completed_tasks)
```

### Callback Not Called
```python
# Ensure main thread doesn't exit
task_id = blockchain.scan_transactions_for_address_async(
    address="LUN_addr",
    callback=my_callback
)

# If script ends immediately, callback might not run
# Keep script alive or wait for completion
status = blockchain.get_task_status(task_id)
while status['status'] == 'running':
    time.sleep(1)
    status = blockchain.get_task_status(task_id)
```

---

## Migration from Sync to Async

### Before (Blocking)
```python
# This blocks your web server for seconds/minutes
transactions = blockchain.scan_transactions_for_address("LUN_addr", 0, 10000)
return jsonify({'transactions': transactions})
```

### After (Non-blocking)
```python
# Returns immediately, web server stays responsive
task_id = blockchain.scan_transactions_for_address_async(
    address="LUN_addr",
    callback=lambda s, r, e: store_result(task_id, r)
)
return jsonify({'task_id': task_id, 'status': 'processing'}), 202
```

---

## Summary

All blocking operations now have `_async` versions:
- ✅ `scan_transactions_for_address_async()`
- ✅ `scan_transactions_for_addresses_async()`
- ✅ `get_blocks_range_async()`
- ✅ `broadcast_transaction_async()`
- ✅ `submit_mined_block_async()`
- ✅ `validate_block_async()` (daemon)
- ✅ `process_incoming_block_async()` (daemon)

All async methods:
1. Return a `task_id` immediately
2. Accept an optional `callback(success, result, error)`
3. Run in background thread pool
4. Can be monitored with `get_task_status(task_id)`
5. Can be cancelled with `cancel_task(task_id)`

Your web interface will now stay responsive even during heavy blockchain operations! 🚀
