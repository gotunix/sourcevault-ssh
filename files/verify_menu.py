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
