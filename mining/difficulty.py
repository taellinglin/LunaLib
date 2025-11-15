import math

class DifficultySystem:
    """Unified difficulty system for mining and transactions"""
    
    def __init__(self):
        # Bill denomination difficulties (1-9 leading zeros)
        self.bill_difficulties = {
            1: 2,           # $1 - Easy
            10: 3,          # $10
            100: 4,         # $100  
            1000: 5,        # $1,000
            10000: 6,       # $10,000
            100000: 7,      # $100,000
            1000000: 8,     # $1,000,000
            10000000: 9,    # $10,000,000
            100000000: 10   # $100,000,000 - Very Hard
        }
        
        # Transaction amount difficulties (logarithmic scaling)
        self.tx_difficulties = {
            (0.000001, 0.001): 1,      # Micro transactions
            (0.001, 0.1): 2,           # Small transactions
            (0.1, 10): 3,              # Regular transactions
            (10, 1000): 4,             # Medium transactions
            (1000, 10000): 5,          # Large transactions
            (10000, 100000): 6,        # Very large
            (100000, 1000000): 7,      # Major transactions
            (1000000, 10000000): 8,    # Significant transfers
            (10000000, 100000000): 9,  # Major transfers
            (100000000, float('inf')): 10  # Maximum security
        }
    
    def get_bill_difficulty(self, denomination):
        """Get mining difficulty for bill denomination"""
        return self.bill_difficulties.get(denomination, 2)
    
    def get_transaction_difficulty(self, amount):
        """Get proof-of-work difficulty for transaction amount"""
        for (min_amt, max_amt), difficulty in self.tx_difficulties.items():
            if min_amt <= amount < max_amt:
                return difficulty
        return 2  # Default
    
    def calculate_mining_reward(self, denomination, mining_time):
        """Calculate reward based on denomination and mining time"""
        base_reward = denomination  # 1:1 ratio with Luna
        
        # Time bonus for faster mining
        if mining_time < 10:
            time_bonus = 1.5
        elif mining_time < 30:
            time_bonus = 1.2
        elif mining_time < 60:
            time_bonus = 1.1
        else:
            time_bonus = 1.0
            
        return base_reward * time_bonus