"""Shared pytest setup (issue #24).

Pin a fixed, wide console width so assertions on Rich-rendered CLI output do not
depend on the terminal width. Rich reads ``COLUMNS`` live from ``os.environ``, so
setting it here at collection time — before the command modules build their
module-level ``Console()`` — keeps rendering stable under any ambient terminal
width (``COLUMNS=60`` and ``COLUMNS=200`` both render at 200 inside the tests).
"""

import os

os.environ["COLUMNS"] = "200"
