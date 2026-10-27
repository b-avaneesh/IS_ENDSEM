"""Hybrid records; textbook RSA numeric product on separate field.
Internal demo users: alice/eve owner, bob reviewer, carol auditor. Rename prompts to match your question."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workbench import main
if __name__ == "__main__":main({'encryption': 'RSA_HYBRID', 'hash_name': 'SHA256', 'signature': 'ELGAMAL', 'he': 'RSA', 'search': 'NONE'})
