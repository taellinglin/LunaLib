#!/usr/bin/env python3
"""Test script to verify wallet transaction retrieval includes all rewards and transfers"""

from lunalib.core.wallet import LunaWallet

def test_wallet_transactions():
    """Test getting all wallet transactions"""
    
    wallet = LunaWallet()
    
    # Load wallets or use existing ones
    try:
        # Try to get list of existing wallets
        wallet_list = wallet.list_wallets()
        
        if wallet_list:
            print(f"\n{'='*60}")
            print(f"Testing wallet transaction retrieval")
            print(f"{'='*60}")
            
            for wallet_addr in wallet_list[:2]:  # Test first 2 wallets
                print(f"\n[*] Processing wallet: {wallet_addr}")
                print(f"{'-'*60}")
                
                # Get comprehensive transaction data
                result = wallet.get_wallet_transactions(wallet_addr, include_pending=True)
                
                # Display results
                print(f"\n[+] Transaction Summary:")
                print(f"   Total Confirmed: {result['total_confirmed']} transactions" if 'total_confirmed' in result else f"   Total Confirmed: {len(result['confirmed'])} transactions")
                print(f"   Mining Rewards: {result['total_rewards']} transactions")
                print(f"   Incoming Transfers: {result['total_incoming']} transactions")
                print(f"   Outgoing Transfers: {result['total_outgoing']} transactions")
                print(f"   Pending: {len(result['pending'])} transactions")
                
                # Show sample rewards
                if result['reward_transactions']:
                    print(f"\n[*] Sample Mining Rewards (first 3):")
                    for i, tx in enumerate(result['reward_transactions'][:3]):
                        print(f"   {i+1}. Block #{tx.get('block_height')}: {tx.get('amount')} LKC")
                    if len(result['reward_transactions']) > 3:
                        print(f"   ... and {len(result['reward_transactions']) - 3} more")
                
                # Show sample incoming transfers
                if result['incoming_transfers']:
                    print(f"\n[*] Sample Incoming Transfers (first 3):")
                    for i, tx in enumerate(result['incoming_transfers'][:3]):
                        print(f"   {i+1}. From {tx.get('from', 'unknown')[:20]}...: {tx.get('amount')} LKC")
                    if len(result['incoming_transfers']) > 3:
                        print(f"   ... and {len(result['incoming_transfers']) - 3} more")
                
                # Show sample outgoing transfers
                if result['outgoing_transfers']:
                    print(f"\n[*] Sample Outgoing Transfers (first 3):")
                    for i, tx in enumerate(result['outgoing_transfers'][:3]):
                        print(f"   {i+1}. To {tx.get('to', 'unknown')[:20]}...: {tx.get('amount')} LKC (fee: {tx.get('fee', 0)})")
                    if len(result['outgoing_transfers']) > 3:
                        print(f"   ... and {len(result['outgoing_transfers']) - 3} more")
                
                # Calculate balance from transactions
                reward_total = sum(float(tx.get('amount', 0)) for tx in result['reward_transactions'])
                incoming_total = sum(float(tx.get('amount', 0)) for tx in result['incoming_transfers'])
                outgoing_total = sum(float(tx.get('amount', 0)) + float(tx.get('fee', 0)) for tx in result['outgoing_transfers'])
                
                print(f"\n[+] Balance Calculation:")
                print(f"   Mining Rewards Total: +{reward_total} LKC")
                print(f"   Incoming Transfers Total: +{incoming_total} LKC")
                print(f"   Outgoing Transfers Total: -{outgoing_total} LKC")
                print(f"   Calculated Balance: {reward_total + incoming_total - outgoing_total} LKC")
                
                # Compare with actual balance
                actual_balance = wallet.get_wallet_balance(wallet_addr)
                print(f"   Actual Balance from get_wallet_balance(): {actual_balance} LKC")
                
        else:
            print("[-] No wallets found. Please create wallets first.")
            
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_wallet_transactions()
