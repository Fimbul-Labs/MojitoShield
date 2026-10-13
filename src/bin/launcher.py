#!/usr/bin/python3 -I
"""Start the installed MojitoShield; the package installs this file as /usr/bin/mojitoshield.

Isolated mode (-I) keeps Python from importing anything from the current folder,
so only the installed copy in /usr/lib/mojitoshield can run.
"""

import sys

sys.path.insert(0, "/usr/lib/mojitoshield")

from mojitoshield.app import main

raise SystemExit(main())
