"""
Web UI Integration Example - Flask Backend

Shows how to integrate the unified wallet system with a web application.
This example demonstrates real-time balance updates sent to a web frontend.
"""

from flask import Flask, jsonify, request
from lunalib.core.wallet import LunaWallet
from lunalib.core.blockchain import BlockchainManager
from lunalib.core.mempool import MempoolManager
import threading
import json

app = Flask(__name__)

# Global state
wallet = LunaWallet()
blockchain = BlockchainManager()
mempool = MempoolManager()

# Store for WebSocket-like updates (in real app, use WebSockets)
wallet_updates = {}


# ============================================================================
# Wallet Setup
# ============================================================================

def initialize_wallets():
    """Initialize with sample wallets"""
    wallet.create_wallet("Main Wallet", "password123")
    wallet.create_new_wallet("Savings", "password456")
    wallet.create_new_wallet("Trading", "password789")


def setup_balance_monitoring():
    """Setup real-time balance monitoring"""
    
    def on_balance_update(balance_data):
        """Callback when balances change - would send WebSocket message in real app"""
        wallet_updates['balances'] = balance_data
        wallet_updates['timestamp'] = __import__('time').time()
        print(f"✅ Balance update: {len(balance_data)} wallets updated")
    
    # Register callback
    wallet.register_wallet_ui_callback(on_balance_update)
    
    # Start continuous sync in background
    wallet.start_continuous_sync(blockchain, mempool, poll_interval=30)


# ============================================================================
# REST API Endpoints
# ============================================================================

@app.route('/api/wallets', methods=['GET'])
def get_all_wallets():
    """Get list of all wallets with current balance"""
    try:
        wallets = []
        for address, wallet_data in wallet.wallets.items():
            details = wallet.get_wallet_details(address)
            if details:
                wallets.append({
                    'address': address,
                    'label': wallet_data.get('label', 'Wallet'),
                    'balance': details['balance']
                })
        
        return jsonify({
            'success': True,
            'data': wallets
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/wallets/<address>/balance', methods=['GET'])
def get_wallet_balance(address):
    """Get detailed balance for a specific wallet"""
    try:
        details = wallet.get_wallet_details(address)
        if not details:
            return jsonify({'success': False, 'error': 'Wallet not found'}), 404
        
        return jsonify({
            'success': True,
            'data': details['balance']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/wallets/<address>/transactions', methods=['GET'])
def get_wallet_transactions(address):
    """Get transactions for a wallet"""
    try:
        tx_type = request.args.get('type', 'all')
        transactions = wallet.get_wallet_transactions(address, tx_type=tx_type)
        
        return jsonify({
            'success': True,
            'data': {
                'type': tx_type,
                'count': len(transactions),
                'transactions': transactions[:50]  # Limit to 50
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/wallets/<address>/summary', methods=['GET'])
def get_wallet_summary(address):
    """Get complete wallet summary"""
    try:
        summary = wallet.get_wallet_summary(address)
        if not summary:
            return jsonify({'success': False, 'error': 'Wallet not found'}), 404
        
        return jsonify({
            'success': True,
            'data': summary
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/wallets/<address>/send', methods=['POST'])
def send_transaction(address):
    """Send transaction from wallet"""
    try:
        data = request.json
        to_address = data.get('to')
        amount = float(data.get('amount', 0))
        memo = data.get('memo', '')
        password = data.get('password', '')
        
        # Validate
        if not to_address or amount <= 0:
            return jsonify({'success': False, 'error': 'Invalid parameters'}), 400
        
        # Switch to wallet and unlock
        if not wallet.switch_wallet(address, password):
            return jsonify({'success': False, 'error': 'Cannot unlock wallet'}), 400
        
        # Send
        success = wallet.send_transaction(to_address, amount, memo)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Transaction sent'
            })
        else:
            return jsonify({'success': False, 'error': 'Transaction failed'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/sync', methods=['POST'])
def manual_sync():
    """Manually trigger wallet sync"""
    try:
        summaries = wallet.sync_with_state_manager(blockchain, mempool)
        
        return jsonify({
            'success': True,
            'synced_wallets': len(summaries),
            'data': summaries
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/wallet-updates', methods=['GET'])
def get_wallet_updates():
    """Get latest wallet updates (for polling-based clients)"""
    return jsonify({
        'success': True,
        'data': wallet_updates
    })


# ============================================================================
# Frontend HTML/JavaScript Example
# ============================================================================

FRONTEND_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Luna Wallet Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .wallet-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .wallet-header {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .balance {
            font-size: 24px;
            color: #2ecc71;
            margin: 10px 0;
        }
        .label {
            color: #666;
            font-size: 12px;
            margin-top: 10px;
        }
        .pending {
            color: #f39c12;
            font-size: 14px;
        }
        .action-button {
            background: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 10px;
            width: 100%;
        }
        .action-button:hover {
            background: #2980b9;
        }
        .update-time {
            color: #999;
            font-size: 11px;
            margin-top: 10px;
        }
        .refresh-button {
            background: #27ae60;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <h1>💰 Luna Wallet Dashboard</h1>
    
    <button class="refresh-button" onclick="manualSync()">🔄 Manual Sync</button>
    
    <div class="container" id="wallets-container">
        <p>Loading wallets...</p>
    </div>

    <script>
        // Configuration
        const API_URL = '/api';
        const POLL_INTERVAL = 5000;  // Poll every 5 seconds
        
        // Load wallets on page load
        window.onload = function() {
            loadWallets();
            setInterval(loadWallets, POLL_INTERVAL);
        };
        
        async function loadWallets() {
            try {
                const response = await fetch(`${API_URL}/wallets`);
                const result = await response.json();
                
                if (result.success) {
                    displayWallets(result.data);
                }
            } catch (error) {
                console.error('Error loading wallets:', error);
            }
        }
        
        function displayWallets(wallets) {
            const container = document.getElementById('wallets-container');
            
            if (!wallets.length) {
                container.innerHTML = '<p>No wallets found</p>';
                return;
            }
            
            let html = '';
            
            wallets.forEach(wallet => {
                const balance = wallet.balance;
                const hasLocked = balance.pending_outgoing > 0;
                
                html += `
                    <div class="wallet-card">
                        <div class="wallet-header">${wallet.label}</div>
                        <div style="font-family: monospace; font-size: 11px; color: #999;">
                            ${wallet.address.substring(0, 20)}...
                        </div>
                        
                        <div class="balance">
                            ${balance.available_balance.toFixed(2)} LUN
                        </div>
                        
                        <div class="label">
                            Confirmed: ${balance.confirmed_balance.toFixed(2)} LUN
                        </div>
                        
                        ${hasLocked ? `
                            <div class="pending">
                                ⏳ Pending: ${balance.pending_outgoing.toFixed(2)} LUN
                            </div>
                        ` : ''}
                        
                        ${balance.pending_incoming > 0 ? `
                            <div class="pending">
                                ↓ Incoming: ${balance.pending_incoming.toFixed(2)} LUN
                            </div>
                        ` : ''}
                        
                        <button class="action-button" onclick="viewDetails('${wallet.address}')">
                            View Details
                        </button>
                        
                        <div class="update-time">
                            Updated: ${new Date().toLocaleTimeString()}
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        }
        
        async function manualSync() {
            try {
                const response = await fetch(`${API_URL}/sync`, {method: 'POST'});
                const result = await response.json();
                
                if (result.success) {
                    alert(`✅ Synced ${result.synced_wallets} wallets`);
                    loadWallets();
                } else {
                    alert(`❌ Sync failed: ${result.error}`);
                }
            } catch (error) {
                alert(`Error: ${error}`);
            }
        }
        
        function viewDetails(address) {
            // In real app, navigate to detailed view
            alert('View details for: ' + address);
        }
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    """Serve the frontend HTML"""
    return FRONTEND_HTML


# ============================================================================
# Start Server
# ============================================================================

if __name__ == '__main__':
    print("🚀 Initializing Luna Wallet API Server...")
    
    # Setup wallets
    print("📱 Creating sample wallets...")
    initialize_wallets()
    
    # Setup monitoring
    print("🔄 Starting background sync...")
    setup_balance_monitoring()
    
    print("✅ Server ready!")
    print("📊 Dashboard: http://localhost:5000")
    print("🔗 API Base: http://localhost:5000/api")
    
    # Start Flask server
    app.run(debug=True, port=5000, use_reloader=False)
