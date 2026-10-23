"""Entry point used by PyInstaller when freezing the CLI.

Kept separate from ``secure_oc/__main__.py`` because a frozen binary cannot
use the ``python -m secure_oc`` form.
"""

import sys

from secure_oc.cli import main

if __name__ == "__main__":
    sys.exit(main())
