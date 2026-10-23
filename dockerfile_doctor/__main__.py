"""Entry point for python -m dockerfile_doctor."""

import sys
from dockerfile_doctor.cli import main

if __name__ == "__main__":
    sys.exit(main())
