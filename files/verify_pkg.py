# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 GOTUNIX Networks <code@gotunix.net>
# SPDX-FileCopyrightText: 2026 Justin Ovens <code@gotunix.net>
# ----------------------------------------------------------------------------------------------- #
#                 $$$$$$\   $$$$$$\ $$$$$$$$\ $$\\   $$\ $$\\   $$\ $$$$$$\ $$\\   $$\               #
#                $$  __$$\ $$  __$$\\__$$  __|$$ |  $$ |$$$\\  $$ |\\_$$  _|$$ |  $$ |              #
#                $$ /  \\__|$$ /  $$ |  $$ |   $$ |  $$ |$$$$\\ $$ |  $$ |  \\$$\\ $$  |              #
#                $$ |$$$$\\ $$ |  $$ |  $$ |   $$ |  $$ |$$ $$\\$$ |  $$ |   \\$$$$  /               #
#                $$ |\\_$$ |$$ |  $$ |  $$ |   $$ |  $$ |$$ \\$$$$ |  $$ |   $$  $$<                #
#                $$ |  $$ |$$ |  $$ |  $$ |   $$ |  $$ |$$ |\\$$$ |  $$ |  $$  /\\$$\\               #
#                \\$$$$$$  | $$$$$$  |  $$ |   \\$$$$$$  |$$ | \\$$ |$$$$$$\\ $$ /  $$ |              #
#                 \\______/  \\______/   \\__|    \\______/ \\__|  \\__|\\______|\\__|  \\__|              #
# ----------------------------------------------------------------------------------------------- #
# Copyright (C) GOTUNIX Networks                                                                  #
# Copyright (C) Justin Ovens                                                                      #
# ----------------------------------------------------------------------------------------------- #
# This program is free software: you can redistribute it and/or modify                            #
# it under the terms of the GNU Affero General Public License as                                  #
# published by the Free Software Foundation, either version 3 of the                              #
# License, or (at your option) any later version.                                                 #
#                                                                                                 #
# This program is distributed in the hope that it will be useful,                                 #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                                 #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   #
# GNU Affero General Public License for more details.                                             #
#                                                                                                 #
# You should have received a copy of the GNU Affero General Public License                        #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.                          #
# ----------------------------------------------------------------------------------------------- #

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
