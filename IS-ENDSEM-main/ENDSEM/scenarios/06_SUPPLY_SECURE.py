"""Buyer -> Supplier; approve/reject; numeric product.
Internal demo users: alice/eve owner, bob reviewer, carol auditor. Rename prompts to match your question."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workbench import main
if __name__ == "__main__":main({'encryption': 'AES_CTR', 'hash_name': 'SHA256', 'signature': 'SCHNORR', 'he': 'ELGAMAL', 'search': 'SSE'})
