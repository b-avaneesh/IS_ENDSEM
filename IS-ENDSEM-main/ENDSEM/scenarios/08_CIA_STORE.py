"""Owner -> Authorized User; auditor; verify and revoke.
Internal demo users: alice/eve owner, bob reviewer, carol auditor. Rename prompts to match your question."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workbench import main
if __name__ == "__main__":main({'encryption': 'ECC_HYBRID', 'hash_name': 'SHA512', 'signature': 'ECDSA', 'he': 'NONE', 'search': 'SSE'})
