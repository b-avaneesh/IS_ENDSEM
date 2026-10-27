# MODIFICATION:
# Syllabus-grounded combination exercise. This is a student-friendly addition derived from the official exercise; no source listing was supplied.

from pathlib import Path
import hashlib
p=Path(input('File path: ')); data=p.read_bytes(); Path(str(p)+'.sha256').write_text(hashlib.sha256(data).hexdigest()); print('Integrity sidecar written; combine with Lab 3 hybrid encryption for confidentiality')
