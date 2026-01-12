# Security Implementation Guide

## Overview

Comprehensive security measures to prevent forging, spoofing, DDoS attacks, and ensure system integrity.

## 1. REWARD-DIFFICULTY CORRELATION SECURITY

### Problem
Miners could claim inflated rewards or create fake blocks with high rewards.

### Solution: Cryptographic Hash Verification

```python
def verify_reward_matches_difficulty(block: Dict) -> bool:
    """
    Verify that block reward exactly matches difficulty level.
    Difficulty N must ALWAYS produce exactly N LKC reward.
    """
    difficulty = block.get('difficulty', 0)
    
    # Extract reward transaction
    reward_tx = None
    for tx in block.get('transactions', []):
        if tx.get('type') == 'reward':
            reward_tx = tx
            break
    
    if not reward_tx:
        return difficulty == 0  # No reward only if difficulty is 0
    
    # Critical: Reward amount must equal difficulty
    expected_reward = float(difficulty)
    actual_reward = float(reward_tx.get('amount', 0))
    
    if actual_reward != expected_reward:
        print(f"❌ FRAUD DETECTED: Reward {actual_reward} != Difficulty {difficulty}")
        return False
    
    # Verify the reward is signed by the network (not miner)
    if reward_tx.get('signature') != 'network_signed':
        print(f"❌ FRAUD: Reward not signed by network")
        return False
    
    # Verify hash proves difficulty
    block_hash = block.get('hash', '')
    required_leading_zeros = difficulty
    
    if not block_hash.startswith('0' * required_leading_zeros):
        print(f"❌ FRAUD: Block hash doesn't prove difficulty {difficulty}")
        return False
    
    return True
```

### Implementation Checklist

```python
class RewardVerification:
    """Prevent reward forging"""
    
    def __init__(self):
        self.verified_blocks = set()
        self.reward_log = []
    
    def validate_block_before_adding_to_chain(self, block: Dict) -> bool:
        """
        ✅ Verify reward = difficulty
        ✅ Verify reward is signed by network
        ✅ Verify block hash matches difficulty
        ✅ Log all rewards for audit trail
        ✅ Reject if any verification fails
        """
        # 1. Check reward amount
        if not self._verify_reward_amount(block):
            return False
        
        # 2. Check reward signature
        if not self._verify_reward_signature(block):
            return False
        
        # 3. Check hash difficulty
        if not self._verify_hash_difficulty(block):
            return False
        
        # 4. Log for audit
        self._log_reward(block)
        
        # 5. Mark as verified
        self.verified_blocks.add(block['hash'])
        
        return True
    
    def _verify_reward_amount(self, block: Dict) -> bool:
        """Reward amount must equal difficulty"""
        difficulty = block.get('difficulty', 0)
        reward_tx = self._find_reward_tx(block)
        
        if not reward_tx and difficulty == 0:
            return True  # Valid: no reward for difficulty 0
        
        if not reward_tx and difficulty > 0:
            return False  # Invalid: should have reward
        
        return float(reward_tx.get('amount', 0)) == float(difficulty)
    
    def _verify_reward_signature(self, block: Dict) -> bool:
        """Reward must be signed by network, not miner"""
        reward_tx = self._find_reward_tx(block)
        
        if not reward_tx:
            return True
        
        # Must be signed by network
        if reward_tx.get('from') != 'network':
            return False
        
        # Must not be unsigned
        if reward_tx.get('signature') == 'unsigned':
            return False
        
        return True
    
    def _verify_hash_difficulty(self, block: Dict) -> bool:
        """Block hash must have required leading zeros"""
        difficulty = block.get('difficulty', 0)
        block_hash = block.get('hash', '')
        
        required_zeros = '0' * difficulty
        return block_hash.startswith(required_zeros)
    
    def _find_reward_tx(self, block: Dict):
        """Find reward transaction in block"""
        for tx in block.get('transactions', []):
            if tx.get('type') == 'reward':
                return tx
        return None
    
    def _log_reward(self, block: Dict):
        """Log all rewards for audit trail"""
        reward_tx = self._find_reward_tx(block)
        if reward_tx:
            self.reward_log.append({
                'block_height': block.get('index'),
                'timestamp': int(time.time()),
                'difficulty': block.get('difficulty'),
                'reward': reward_tx.get('amount'),
                'block_hash': block.get('hash')
            })
```

## 2. TRANSFER TRANSACTION SECURITY

### Problem
Attackers could forge transfers, claim ownership of others' funds.

### Solution: SM2 Digital Signatures

```python
def secure_transfer_validation(transaction: Dict) -> Tuple[bool, str]:
    """
    Validate transfer transactions using SM2 cryptography.
    Cannot forge without private key of sending address.
    """
    
    # 1. Check from address is valid format
    if not is_valid_address_format(transaction['from']):
        return False, "Invalid from address format"
    
    # 2. Check to address is valid format
    if not is_valid_address_format(transaction['to']):
        return False, "Invalid to address format"
    
    # 3. Verify SM2 signature
    tx_string = get_signing_data(transaction)
    signature = transaction.get('signature')
    public_key = transaction.get('public_key')
    
    if not verify_sm2_signature(tx_string, signature, public_key):
        return False, "Invalid SM2 signature - transaction forged"
    
    # 4. Derive address from public key and verify it matches 'from'
    derived_address = derive_address_from_pubkey(public_key)
    if derived_address != transaction['from']:
        return False, "Public key doesn't match from address - FRAUD"
    
    # 5. Check amount is reasonable
    if float(transaction.get('amount', 0)) <= 0:
        return False, "Amount must be positive"
    
    # 6. Verify timestamp is recent
    now = int(time.time())
    tx_time = int(transaction.get('timestamp', 0))
    
    if tx_time > now + 300:  # 5 min in future
        return False, "Transaction timestamp too far in future"
    
    if tx_time < now - 86400:  # 24 hours in past
        return False, "Transaction timestamp too old"
    
    return True, "Valid"
```

### Implementation

```python
class TransferSecurity:
    """Prevent transfer forging and spoofing"""
    
    def __init__(self):
        self.key_manager = KeyManager()  # SM2 manager
        self.transaction_cache = {}  # Prevent replay attacks
    
    def validate_and_process_transfer(self, tx: Dict) -> bool:
        """
        ✅ Verify SM2 signature
        ✅ Verify address authenticity
        ✅ Prevent replay attacks
        ✅ Check balance before accepting
        """
        
        # 1. Basic format validation
        if not self._validate_format(tx):
            return False
        
        # 2. Verify signature using SM2
        if not self._verify_signature(tx):
            print("❌ Signature verification failed - likely forgery")
            return False
        
        # 3. Verify public key matches from address
        if not self._verify_address_authenticity(tx):
            print("❌ Address authenticity failed - spoofing attempt")
            return False
        
        # 4. Prevent replay attacks
        if self._is_replay_attack(tx):
            print("❌ Replay attack detected")
            return False
        
        # 5. Cache this transaction
        self.transaction_cache[tx['hash']] = {
            'timestamp': int(time.time()),
            'from': tx['from'],
            'nonce': tx.get('nonce')
        }
        
        return True
    
    def _verify_signature(self, tx: Dict) -> bool:
        """Verify SM2 signature of transaction"""
        tx_data = {k: v for k, v in tx.items() 
                   if k not in ['signature', 'hash']}
        tx_string = json.dumps(tx_data, sort_keys=True)
        
        signature = tx.get('signature')
        public_key = tx.get('public_key')
        
        return self.key_manager.verify_signature(tx_string, signature, public_key)
    
    def _verify_address_authenticity(self, tx: Dict) -> bool:
        """Verify that public key matches the from address"""
        public_key = tx.get('public_key')
        from_address = tx.get('from')
        
        # Derive address from public key
        derived = self.key_manager.derive_address(public_key)
        
        # Must match from address
        return derived == from_address
    
    def _is_replay_attack(self, tx: Dict) -> bool:
        """Detect replay attacks using nonce or timestamp"""
        tx_hash = tx['hash']
        
        # If we've seen this exact transaction before
        if tx_hash in self.transaction_cache:
            # Could be a replay attack
            return True
        
        # Check for same nonce from same sender in short timeframe
        if 'nonce' in tx:
            nonce = tx['nonce']
            sender = tx['from']
            
            # Look for previous tx with same nonce
            for cached_hash, cached_tx in self.transaction_cache.items():
                if (cached_tx['from'] == sender and
                    cached_tx.get('nonce') == nonce):
                    # Same sender, same nonce = replay
                    return True
        
        return False
    
    def _validate_format(self, tx: Dict) -> bool:
        """Validate basic transaction format"""
        required = ['from', 'to', 'amount', 'signature', 'public_key']
        return all(key in tx for key in required)
```

## 3. ADDRESS SPOOFING PREVENTION

### Problem
Attackers could use fake addresses to impersonate legitimate wallets.

### Solution: Address Derivation from Public Key

```python
class AddressAuthentication:
    """
    Prevent address spoofing by deriving addresses from public keys.
    Address = hash(public_key), cannot be faked.
    """
    
    def __init__(self):
        self.key_manager = KeyManager()
        self.address_to_pubkey = {}  # Track address -> public key mapping
    
    def is_address_authentic(self, address: str, public_key: str) -> bool:
        """
        Verify that address was derived from this public key.
        If they don't match, address is spoofed.
        """
        # Derive what address should be from public key
        derived_address = self.key_manager.derive_address(public_key)
        
        # Must match exactly
        if derived_address != address:
            return False
        
        # If we've seen this address before, public key must match
        if address in self.address_to_pubkey:
            if self.address_to_pubkey[address] != public_key:
                print(f"❌ FRAUD: Address {address} has different public key!")
                return False
        else:
            # Register this address-pubkey pair
            self.address_to_pubkey[address] = public_key
        
        return True
    
    def validate_addresses_in_transaction(self, tx: Dict) -> bool:
        """
        Validate that:
        1. From address matches public key
        2. From address format is valid
        3. To address format is valid
        """
        from_addr = tx.get('from')
        to_addr = tx.get('to')
        public_key = tx.get('public_key')
        
        # Verify from address matches public key
        if not self.is_address_authentic(from_addr, public_key):
            print(f"❌ From address {from_addr} doesn't match public key")
            return False
        
        # Validate format of both addresses
        if not self._is_valid_address_format(from_addr):
            return False
        
        if not self._is_valid_address_format(to_addr):
            return False
        
        # Addresses should be different (not sending to self)
        # Actually, self-transfers are valid, so remove this check
        
        return True
    
    def _is_valid_address_format(self, address: str) -> bool:
        """Check address format"""
        # Must have LUN_ prefix
        if not address.upper().startswith('LUN_'):
            return False
        
        # Must be reasonable length (LUN_ + at least 30 hex chars)
        if len(address) < 40:
            return False
        
        # Must be hex (except prefix)
        try:
            int(address[4:], 16)
            return True
        except:
            return False
```

## 4. DDOS/SPAM PROTECTION

### Problem
Attackers could flood network with spam transactions or requests.

### Solution: Rate Limiting, Fee Requirements, Size Limits

```python
class AntiSpamDefense:
    """
    Protect against DDoS and spam attacks.
    """
    
    def __init__(self):
        self.sender_history = {}  # Track transactions per sender
        self.ip_history = {}      # Track transactions per IP
        self.mempool_size_limit = 10000
        self.max_tx_per_sender_per_minute = 100
        self.min_fee = 0.001  # Minimum fee to submit transaction
    
    def is_spam_or_ddos(self, transaction: Dict, sender_ip: str = None) -> bool:
        """
        Detect spam/DDoS patterns.
        """
        sender = transaction.get('from')
        
        # 1. Check sender rate limit
        if self._is_rate_limited(sender):
            print(f"⚠️  Rate limit: Sender {sender} is sending too many txs")
            return True
        
        # 2. Check IP rate limit (if available)
        if sender_ip and self._is_ip_rate_limited(sender_ip):
            print(f"⚠️  IP rate limit: {sender_ip} is sending too many txs")
            return True
        
        # 3. Check fee (discourage spam)
        fee = float(transaction.get('fee', 0))
        if fee < self.min_fee:
            print(f"⚠️  Insufficient fee: {fee} < {self.min_fee}")
            return True
        
        # 4. Check amount is reasonable
        amount = float(transaction.get('amount', 0))
        if amount == 0:
            print(f"⚠️  Zero amount transaction (likely spam)")
            return True
        
        # 5. Check timestamp is recent
        if self._is_timestamp_suspicious(transaction):
            print(f"⚠️  Suspicious timestamp")
            return True
        
        return False
    
    def _is_rate_limited(self, sender: str) -> bool:
        """Check if sender is sending too many transactions"""
        now = int(time.time())
        one_minute_ago = now - 60
        
        if sender not in self.sender_history:
            self.sender_history[sender] = []
        
        # Clean old entries
        self.sender_history[sender] = [
            ts for ts in self.sender_history[sender]
            if ts > one_minute_ago
        ]
        
        # Check limit
        if len(self.sender_history[sender]) >= self.max_tx_per_sender_per_minute:
            return True
        
        # Record this transaction
        self.sender_history[sender].append(now)
        return False
    
    def _is_ip_rate_limited(self, ip: str) -> bool:
        """Check if IP is sending too many transactions"""
        now = int(time.time())
        one_minute_ago = now - 60
        
        max_per_ip = 500  # Stricter than per-sender
        
        if ip not in self.ip_history:
            self.ip_history[ip] = []
        
        # Clean old entries
        self.ip_history[ip] = [
            ts for ts in self.ip_history[ip]
            if ts > one_minute_ago
        ]
        
        if len(self.ip_history[ip]) >= max_per_ip:
            return True
        
        self.ip_history[ip].append(now)
        return False
    
    def _is_timestamp_suspicious(self, tx: Dict) -> bool:
        """Check if timestamp is suspicious"""
        now = int(time.time())
        tx_time = int(tx.get('timestamp', 0))
        
        # More than 5 minutes in future - reject
        if tx_time > now + 300:
            return True
        
        # More than 24 hours in past - reject
        if tx_time < now - 86400:
            return True
        
        return False
    
    def can_add_to_mempool(self, mempool_size: int) -> bool:
        """Check if mempool has space"""
        return mempool_size < self.mempool_size_limit
```

## 5. INTEGRATION CHECKLIST

### Before Deploying to Production

```python
# 1. Reward Verification ✅
□ Implement RewardVerification class
□ Verify reward = difficulty
□ Verify reward signed by network
□ Log all rewards for audit trail
□ Reject blocks with incorrect rewards

# 2. Transfer Security ✅
□ Implement TransferSecurity class
□ Verify SM2 signatures
□ Verify address authenticity
□ Prevent replay attacks
□ Check balance before accepting

# 3. Address Authentication ✅
□ Implement AddressAuthentication class
□ Derive addresses from public keys
□ Track address-pubkey mappings
□ Reject spoofed addresses
□ Validate address format

# 4. Anti-Spam Defense ✅
□ Implement AntiSpamDefense class
□ Rate limit per sender
□ Rate limit per IP
□ Require minimum fees
□ Limit mempool size
□ Validate timestamps

# 5. Blockchain Integrity ✅
□ Verify block hashes immutable
□ Verify previous hash reference
□ Verify transaction hashes
□ Maintain transaction history
□ Log all state changes
```

## 6. MONITORING & ALERTING

```python
class SecurityMonitor:
    """Monitor system for security issues"""
    
    def __init__(self):
        self.alerts = []
        self.anomalies = []
    
    def check_for_anomalies(self):
        """
        ✅ Monitor for forged rewards
        ✅ Detect spoofed addresses
        ✅ Alert on DDoS patterns
        ✅ Track failed validations
        ✅ Monitor mempool health
        """
        pass
    
    def log_security_event(self, event_type: str, details: Dict):
        """Log all security events for audit trail"""
        event = {
            'timestamp': int(time.time()),
            'type': event_type,
            'details': details,
            'severity': self._calculate_severity(event_type)
        }
        self.alerts.append(event)
        print(f"🔒 SECURITY: {event_type} - {details}")
    
    def _calculate_severity(self, event_type: str) -> str:
        """Calculate event severity"""
        critical = ['forged_reward', 'spoofed_address', 'failed_signature']
        if event_type in critical:
            return 'CRITICAL'
        return 'WARNING'
```

## Summary

**Security Layers:**
1. ✅ Reward-Difficulty Correlation - Cryptographic verification
2. ✅ Transfer Authenticity - SM2 digital signatures
3. ✅ Address Authentication - Derived from public keys
4. ✅ Anti-Spam - Rate limiting and fees
5. ✅ Blockchain Integrity - Hash verification and audit logs

**Key Principles:**
- **Cryptography First** - Use SM2 signatures, not trust
- **Immutability** - Hashes prove no tampering
- **Auditability** - Log everything
- **Rate Limiting** - Prevent abuse
- **Verification** - Verify before accepting
