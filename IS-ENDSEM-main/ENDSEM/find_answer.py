"""Filter all combinations, then run or export the selected ID."""
import json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
rows=json.loads((ROOT/'COMBINATION_INDEX.json').read_text())
for field in ('encryption','hash_name','signature','he','search'):
    options=sorted({r[field] for r in rows});print('\n'+field+': '+', '.join(options))
    value=input('Choose one (Enter=any): ').strip().upper()
    if value:rows=[r for r in rows if r[field]==value]
    if not rows:print('No match. Restart and use an exact option.');sys.exit(1)
for r in rows[:100]:print(r['id'],r['path'])
print('Matches:',len(rows),'; showing first 100. Full list: COMBINATION_INDEX.txt')
ident=input('ID to export/run (Enter=exit): ').strip()
if ident:
    r=next((r for r in rows if str(r['id'])==ident),None)
    if r is None:raise SystemExit('ID is outside your filtered matches')
    choice=input('1 Export standalone / 2 Run menu / 3 Run demo: ')
    if choice=='1':
        from build_combinations import export
        export(int(ident))
    else:
        args=[sys.executable,str(ROOT/r['path'])]
        if choice=='3':args.append('--demo')
        subprocess.run(args,check=True)
