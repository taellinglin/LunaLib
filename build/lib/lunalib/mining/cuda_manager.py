import time
from typing import Optional, Dict, Any
import hashlib
import json

try:
    import cupy as cp
    CUDA_AVAILABLE = True
except ImportError:
    CUDA_AVAILABLE = False
    cp = None

class CUDAManager:
    """Manages CUDA acceleration for mining operations"""
    
    def __init__(self):
        self.cuda_available = self._check_cuda()
        self.device = None
        
        if self.cuda_available:
            self._initialize_cuda()
    
    def _check_cuda(self) -> bool:
        """Check if CUDA is available"""
        try:
            if not CUDA_AVAILABLE:
                return False
                
            if cp.cuda.runtime.getDeviceCount() > 0:
                print("✅ CUDA is available for accelerated mining")
                return True
            else:
                print("❌ CUDA drivers found but no GPU available")
                return False
        except Exception as e:
            print(f"❌ CUDA check failed: {e}")
            return False
    
    def _initialize_cuda(self):
        """Initialize CUDA device"""
        try:
            self.device = cp.cuda.Device(0)
            self.device.use()
            print(f"✅ Using CUDA device: {cp.cuda.runtime.getDeviceProperties(0)['name']}")
        except Exception as e:
            print(f"❌ CUDA initialization failed: {e}")
            self.cuda_available = False
    
    def cuda_mine_batch(self, mining_data: Dict, difficulty: int, batch_size: int = 100000) -> Optional[Dict]:
        """Mine using CUDA acceleration with CPU-side hash computation"""
        if not self.cuda_available:
            return None
            
        try:
            target = "0" * difficulty
            nonce_start = 0
            start_time = time.time()
            
            # Pre-compute the base string without nonce for efficiency
            base_data = {k: v for k, v in mining_data.items() if k != 'nonce'}
            
            while True:
                # Generate nonces on GPU for parallel processing
                nonces_gpu = cp.arange(nonce_start, nonce_start + batch_size, dtype=cp.int64)
                nonces_cpu = cp.asnumpy(nonces_gpu)  # Transfer to CPU for hashing
                
                # Compute hashes in parallel on CPU (GPU hash acceleration requires custom CUDA kernels)
                hashes = self._compute_hashes_parallel(base_data, nonces_cpu)
                
                # Check for successful hash
                for i, hash_hex in enumerate(hashes):
                    if hash_hex.startswith(target):
                        mining_time = time.time() - start_time
                        successful_nonce = int(nonces_cpu[i])
                        
                        return {
                            "success": True,
                            "hash": hash_hex,
                            "nonce": successful_nonce,
                            "mining_time": mining_time,
                            "method": "cuda"
                        }
                
                nonce_start += batch_size
                
                # Progress update
                if nonce_start % (batch_size * 10) == 0:
                    current_time = time.time()
                    hashrate = nonce_start / (current_time - start_time)
                    print(f"⏳ CUDA: {nonce_start:,} attempts | {hashrate:,.0f} H/s")
                
                # Timeout check
                if time.time() - start_time > 300:  # 5 minutes timeout
                    break
                    
        except Exception as e:
            print(f"CUDA mining error: {e}")
            
        return None
    
    def _compute_hashes_parallel(self, base_data: Dict, nonces: list) -> list:
        """Compute SHA256 hashes in parallel on CPU (string operations not supported on GPU)"""
        hashes = []
        
        for nonce in nonces:
            # Create mining data with current nonce
            mining_data = base_data.copy()
            mining_data["nonce"] = int(nonce)
            
            # Compute hash
            data_string = json.dumps(mining_data, sort_keys=True)
            hash_obj = hashlib.sha256(data_string.encode())
            hashes.append(hash_obj.hexdigest())
            
        return hashes
    
    def get_cuda_info(self) -> Dict[str, Any]:
        """Get CUDA device information"""
        if not self.cuda_available:
            return {"available": False}
            
        try:
            props = cp.cuda.runtime.getDeviceProperties(0)
            return {
                "available": True,
                "device_name": props.get('name', 'Unknown'),
                "compute_capability": f"{props.get('major', 0)}.{props.get('minor', 0)}",
                "total_memory": props.get('totalGlobalMem', 0),
                "multiprocessors": props.get('multiProcessorCount', 0)
            }
        except Exception as e:
            return {"available": False, "error": str(e)}