import os
import json
import time
import hashlib
import secrets
from typing import Dict, List, Optional
from ..storage.encryption import EncryptionManager
from ..crypto import KeyManager

class LunaWallet:
    """Main wallet class for key management and operations"""
    
    def __init__(self, data_dir=None):
        self.data_dir = data_dir or os.path.join(os.path.expanduser("~"), ".luna_wallet")
        os.makedirs(self.data_dir, exist_ok=True)
        
        self.encryption = EncryptionManager()
        self.key_manager = KeyManager()
        self.wallets = []
        self.is_unlocked = False
        
    def create_wallet(self, label="Primary Wallet", password=None):
        """Create a new wallet with encrypted storage"""
        private_key = self.key_manager.generate_private_key()
        public_key = self.key_manager.derive_public_key(private_key)
        address = self.key_manager.derive_address(public_key)
        
        wallet_data = {
            "address": address,
            "label": label,
            "public_key": public_key,
            "private_key": private_key,  # Will be encrypted
            "balance": 0.0,
            "created": time.time(),
            "transactions": []
        }
        
        if password:
            encrypted_data = self.encryption.encrypt_wallet(wallet_data, password)
            self._save_wallet_file(address, encrypted_data)
        
        self.wallets.append(wallet_data)
        return wallet_data
    
    def unlock_wallet(self, address, password):
        """Unlock wallet with password"""
        encrypted_data = self._load_wallet_file(address)
        if encrypted_data:
            wallet_data = self.encryption.decrypt_wallet(encrypted_data, password)
            if wallet_data:
                self.wallets.append(wallet_data)
                self.is_unlocked = True
                return True
        return False
    
    def export_private_key(self, address, password):
        """Export private key for backup"""
        if not self.is_unlocked:
            return None
            
        wallet = next((w for w in self.wallets if w["address"] == address), None)
        if wallet and self.encryption.verify_password(password):
            return wallet["private_key"]
        return None
    
    def _save_wallet_file(self, address, data):
        """Save wallet to file"""
        filename = f"wallet_{address}.dat"
        filepath = os.path.join(self.data_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f)
    
    def _load_wallet_file(self, address):
        """Load wallet from file"""
        filename = f"wallet_{address}.dat"
        filepath = os.path.join(self.data_dir, filename)
        
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        return None