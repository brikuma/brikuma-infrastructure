"""Install only when no existing effective hook setup would be replaced."""
import os
from pathlib import Path
import subprocess
import sys
current = subprocess.run(['git','config','--get','core.hooksPath'],capture_output=True,text=True)
if current.returncode not in (0,1) or current.stdout.strip() not in ('','.githooks'):
    sys.exit('Existing effective hook configuration requires deliberate composition; nothing changed.')
if not current.stdout.strip():
    result = subprocess.run(['git','rev-parse','--git-path','hooks'],capture_output=True,text=True,check=True)
    hooks = Path(result.stdout.strip())
    if hooks.exists() and any(p.is_file() and not p.name.endswith('.sample') and os.access(p, os.X_OK) for p in hooks.iterdir()):
        sys.exit('Existing executable Git hooks require deliberate composition; nothing changed.')
subprocess.run(['git','config','--local','core.hooksPath','.githooks'],check=True)
print('Repository-local documentation/privacy hooks installed.')
