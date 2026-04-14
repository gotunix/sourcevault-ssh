
import sys
from unittest.mock import MagicMock
import git_shell.main

# Mock ensure_server_key to avoid GPG requirement for UI test
git_shell.main.ensure_server_key = MagicMock()

print("Launching UI verification...")
try:
    # Verify the menu runs. User will need to F3 to exit.
    git_shell.main.interactive_menu(["user-test", "interactive"], "key-test")
except SystemExit:
    print("Exited cleanly.")
except KeyboardInterrupt:
    print("Interrupted.")
except Exception as e:
    print(f"Error: {e}")
