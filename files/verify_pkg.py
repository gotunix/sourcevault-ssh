
import os
import shutil
from git_shell.main import create_repo_callback, check_authorization

# Setup Env
repo_root = "/home/jovens/code/docker/ssh/files/tmp_repos_pkg"
if os.path.exists(repo_root):
    shutil.rmtree(repo_root)
os.environ["GIT_SHELL_REPO_ROOT"] = repo_root

# Setup Logging (to stderr)
import logging
logging.basicConfig(level=logging.DEBUG)

print(f"Testing with REPO_ROOT={repo_root}")

principals = ["user-test", "interactive"]
repo = "pkgrepo"
org = "test"
project = ""

print("Calling create_repo_callback...")
success, msg = create_repo_callback(principals, repo, project, org)
print(f"Success: {success}")
print(f"Message: {msg}")

if success:
    expected_path = os.path.join(repo_root, "users", "test", "pkgrepo.git")
    if os.path.exists(expected_path):
        print("VERIFIED: Directory created.")
    else:
        print(f"FAILED: Directory not found at {expected_path}")
else:
    print("FAILED: valid creation failed.")
