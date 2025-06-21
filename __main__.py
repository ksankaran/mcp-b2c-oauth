"""Main entry point for simple MCP server with GitHub OAuth authentication."""

import sys

from server import main

sys.exit(main())  # type: ignore[call-arg]