import time
import hashlib
import json
from typing import Dict, Optional
from .security import TransactionSecurity
from ..crypto import KeyManager

class TransactionManager:
    """Handles transaction creation, signing, and validation"""
    
    def __init__(self):
        self.security = TransactionSecurity()
        self.key_manager = KeyManager()
    
    def create_transaction(self, from_address, to_address, amount, private_key, memo=""):
        """Create and sign a transaction"""
        transaction = {
            "type": "transfer",
            "from": from_address,
            "to": to_address,
            "amount": float(amount),
            "fee": 0.00001,
            "nonce": int(time.time() * 1000),
            "timestamp": time.time(),
            "memo": memo,
            "public_key": self.key_manager.derive_public_key(private_key)
        }
        
        # Sign transaction
        sign_data = self._get_signing_data(transaction)
        signature = self.key_manager.sign_data(sign_data, private_key)
        
        transaction["signature"] = signature
        transaction["hash"] = self._calculate_transaction_hash(transaction)
        
        return transaction
    
    def create_gtx_transaction(self, bill_info):
        """Create GTX Genesis transaction from mined bill"""
        return bill_info["transaction_data"]
    
    def create_reward_transaction(self, to_address, amount, block_height):
        """Create block reward transaction"""
        transaction = {
            "type": "reward",
            "from": "network",
            "to": to_address,
            "amount": float(amount),
            "block_height": block_height,
            "timestamp": time.time(),
            "hash": self._generate_reward_hash(to_address, amount, block_height)
        }
        
        return transaction
    
    def _get_signing_data(self, transaction):
        """Create data string for signing"""
        parts = [
            transaction["from"],
            transaction["to"],
            str(transaction["amount"]),
            str(transaction["nonce"]),
            str(transaction["timestamp"]),
            transaction.get("memo", "")
        ]
        return "".join(parts)
    
    def _calculate_transaction_hash(self, transaction):
        """Calculate transaction hash"""
        data_string = json.dumps(transaction, sort_keys=True)
        return hashlib.sha256(data_string.encode()).hexdigest()
    
    def _generate_reward_hash(self, to_address, amount, block_height):
        """Generate unique hash for reward transaction"""
        data = f"reward_{to_address}_{amount}_{block_height}_{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()