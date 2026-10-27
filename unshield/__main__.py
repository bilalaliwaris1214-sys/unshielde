import sys

from .cli import main

try:
    code = main()
    sys.stdout.flush()
except BrokenPipeError:      # e.g. `unshield ... | head`
    code = 0
sys.exit(code)
