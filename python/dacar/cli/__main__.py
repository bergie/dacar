"""Allow ``python -m dacar.cli`` to run the CLI."""

import sys

from dacar.cli import main

if __name__ == "__main__":
    sys.exit(main())
