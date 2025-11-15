import time
import hashlib
import secrets
from typing import Dict, Optional
from .bill_registry import BillRegistry

class DigitalBill:
    """Represents a GTX Genesis digital bill"""
    
    def __init__(self, denomination, user_address, difficulty, bill_data=None):
        self.denomination = denomination
        self.user_address = user_address
        self.difficulty = difficulty
        self.bill_data = bill_data or {}
        self.bill_serial = self._generate_serial()
        self.created_time = time.time()
        self.bill_registry = BillRegistry()
        
    def _generate_serial(self):
        """Generate unique bill serial number"""
        timestamp = int(time.time() * 1000)
        random_part = secrets.token_hex(4)
        return f"GTX{self.denomination}_{timestamp}_{random_part}"
    
    def get_mining_data(self, nonce):
        """Get data for mining computation"""
        return {
            "type": "GTX_Genesis",
            "denomination": self.denomination,
            "user_address": self.user_address,
            "bill_serial": self.bill_serial,
            "timestamp": self.created_time,
            "difficulty": self.difficulty,
            "previous_hash": self._get_previous_hash(),
            "nonce": nonce,
            "bill_data": self.bill_data
        }
    
    def finalize(self, hash, nonce, mining_time):
        """Finalize bill after successful mining"""
        bill_info = {
            "success": True,
            "bill_serial": self.bill_serial,
            "denomination": self.denomination,
            "user_address": self.user_address,
            "mining_time": mining_time,
            "difficulty": self.difficulty,
            "hash": hash,
            "nonce": nonce,
            "timestamp": time.time(),
            "luna_value": self.denomination,  # 1:1 ratio
            "transaction_data": {
                "type": "GTX_Genesis",
                "from": "genesis_network",
                "to": self.user_address,
                "amount": self.denomination,
                "bill_serial": self.bill_serial,
                "mining_difficulty": self.difficulty,
                "mining_time": mining_time,
                "hash": hash,
                "timestamp": time.time(),
                "status": "mined"
            }
        }
        
        # Add to bill registry
        self.bill_registry.register_bill(bill_info)
        
        return bill_info
    
    def _get_previous_hash(self):
        """Get hash of previous genesis transaction"""
        # In production, this would query the blockchain
        return hashlib.sha256(str(time.time()).encode()).hexdigest()