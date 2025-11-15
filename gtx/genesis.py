import time
import hashlib
import secrets
from typing import Dict, List, Optional
from .digital_bill import DigitalBill
from .bill_registry import BillRegistry
from ..mining.cuda_manager import CUDAManager

class GTXGenesis:
    """Main GTX Genesis system manager"""
    
    def __init__(self):
        self.bill_registry = BillRegistry()
        self.cuda_manager = CUDAManager()
        self.valid_denominations = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000]
    
    def create_genesis_bill(self, denomination: int, user_address: str, 
                          custom_data: Optional[Dict] = None) -> DigitalBill:
        """Create a new GTX Genesis bill"""
        if denomination not in self.valid_denominations:
            raise ValueError(f"Invalid denomination. Must be one of: {self.valid_denominations}")
        
        bill_data = custom_data or {}
        bill_data.update({
            "creation_timestamp": time.time(),
            "version": "1.0",
            "asset_type": "GTX_Genesis"
        })
        
        return DigitalBill(
            denomination=denomination,
            user_address=user_address,
            difficulty=self._calculate_difficulty(denomination),
            bill_data=bill_data
        )
    
    def verify_bill(self, bill_serial: str) -> Dict:
        """Verify a GTX Genesis bill"""
        bill_info = self.bill_registry.get_bill(bill_serial)
        if not bill_info:
            return {"valid": False, "error": "Bill not found"}
        
        # Verify cryptographic integrity
        is_valid = self._verify_bill_crypto(bill_info)
        
        return {
            "valid": is_valid,
            "bill_info": bill_info,
            "verification_url": bill_info.get('verification_url'),
            "luna_value": bill_info.get('luna_value', 0)
        }
    
    def get_user_portfolio(self, user_address: str) -> Dict:
        """Get user's GTX Genesis portfolio"""
        bills = self.bill_registry.get_user_bills(user_address)
        total_value = sum(bill['luna_value'] for bill in bills)
        
        return {
            "user_address": user_address,
            "total_bills": len(bills),
            "total_luna_value": total_value,
            "bills": bills,
            "breakdown": self._get_denomination_breakdown(bills)
        }
    
    def transfer_bill(self, bill_serial: str, from_address: str, to_address: str, 
                     private_key: str) -> bool:
        """Transfer GTX Genesis bill to another address"""
        # Verify ownership
        bill = self.bill_registry.get_bill(bill_serial)
        if not bill or bill['user_address'].lower() != from_address.lower():
            return False
        
        # In a real implementation, you'd verify the signature
        # For now, we'll update the registry
        return self.bill_registry.transfer_bill(bill_serial, to_address)
    
    def _calculate_difficulty(self, denomination: int) -> int:
        """Calculate mining difficulty based on denomination"""
        # Logarithmic scaling: higher denominations = more zeros
        if denomination <= 1:
            return 2
        elif denomination <= 10:
            return 3
        elif denomination <= 100:
            return 4
        elif denomination <= 1000:
            return 5
        elif denomination <= 10000:
            return 6
        elif denomination <= 100000:
            return 7
        elif denomination <= 1000000:
            return 8
        elif denomination <= 10000000:
            return 9
        else:
            return 10
    
    def _verify_bill_crypto(self, bill_info: Dict) -> bool:
        """Verify bill cryptographic integrity"""
        try:
            # Recreate mining data
            mining_data = {
                "type": "GTX_Genesis",
                "denomination": bill_info['denomination'],
                "user_address": bill_info['user_address'],
                "bill_serial": bill_info['bill_serial'],
                "timestamp": bill_info['timestamp'],
                "difficulty": bill_info['difficulty'],
                "nonce": bill_info['nonce']
            }
            
            # Verify hash matches
            data_string = json.dumps(mining_data, sort_keys=True)
            computed_hash = hashlib.sha256(data_string.encode()).hexdigest()
            
            return computed_hash == bill_info['hash']
            
        except Exception as e:
            print(f"Bill verification error: {e}")
            return False
    
    def _get_denomination_breakdown(self, bills: List[Dict]) -> Dict[int, int]:
        """Get breakdown of bills by denomination"""
        breakdown = {}
        for bill in bills:
            denom = bill['denomination']
            breakdown[denom] = breakdown.get(denom, 0) + 1
        return breakdown