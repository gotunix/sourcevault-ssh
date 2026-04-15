#!/usr/bin/env python3
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
import re
import sys
import time
import shutil
import logging
import pathlib
import subprocess

logging.basicConfig(filename="/git/logs/ssh.log",
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.DEBUG)

epoch = int(time.time())


def get_cert_info():
    if 'SSH_USER_AUTH' not in os.environ:
        logging.debug("SSH_USER_AUTH environemntal variable is not set")
        sys.stderr.write("Unexpected Error")
        exit(1)

    auth_info_path = os.environ.get("SSH_USER_AUTH")
    if not os.path.exists(auth_info_path):
        logging.debug("{} does not exist".format(auth_info_path))
        sys.stderr.write("Unexpected Error")
        exit(1)

    try:
        with open(auth_info_path, 'r') as f:
            content = f.read().strip()

        if content.startswith("publickey "):
            content = content.replace("publickey ", "", 1)

        temp_file = "/tmp/auth." + str(epoch)
        try:
            with open(temp_file, "w") as tf:
                tf.write(content)
        except Exception as e:
            logging.debug("Exception: {}".format(e))
            sys.stderr.write("Unexpected Error")
            exit(1)

    except Exception as e:
        logging.debug("Exception: {}".format(e))
        sys.stderr.write("Unexpected Error")
        exit(1)

    logging.info("Checking certificate information")
    try:
        result = subprocess.run(
            ["ssh-keygen", "-L", "-f", temp_file],
            capture_output=True,
            text=True,
            check=True
        )

        lines = result.stdout.splitlines()
        data = {"key_id": None, "serial": None, "principals": []}

        # We only want to collect lines when this is True
        collecting_principals = False

        # Headers that signal the end of the Principals list
        stop_headers = ["Critical Options:", "Extensions:", "Valid:"]

        for line in lines:
            # 1. Capture Key ID
            if "Key ID:" in line:
                data["key_id"] = line.split(":", 1)[1].strip().replace('"', '')
                continue

            # 2. Capture Serial
            if "Serial:" in line:
                data["serial"] = line.split(":", 1)[1].strip()
                continue

            # 3. Start Principals collection
            if "Principals:" in line:
                collecting_principals = True
                continue

            # 4. Stop Principals collection if we hit the next header
            if any(header in line for header in stop_headers):
                collecting_principals = False
                continue

            # 5. Collect the actual principals
            if collecting_principals:
                clean_line = line.strip()
                # Skip the '(none)' placeholder and empty lines
                if clean_line and clean_line != "(none)":
                    data["principals"].append(clean_line)

        return data
    except subprocess.CalledProcessError as e:
        logging.debug("Exception: {}".format(e))
        sys.stderr.write("Unexpected Error")
        exit(1)

def sanitize_and_execute(original_cmd, cert_data):
    if "git" not in cert_data["principals"]:
        sys.stderr.write("Unauthorized: Missing git principal.\n")
        sys.exit(1)

    if not original_cmd:
        # No command: Allow interactive git-shell if configured
        os.execv("/usr/bin/git-shell", ["git-shell"])

    # 1. Whitelist the allowed Git executables
    allowed_executables = [
        "git-upload-pack", 
        "git-receive-pack", 
        "git-upload-archive", 
        "git-lfs-authenticate"
    ]

    # 2. Split the command into parts (e.g., ["git-upload-pack", "'repo.git'"])
    parts = original_cmd.split()
    executable = parts[0]

    if executable not in allowed_executables:
        sys.stderr.write(f"Forbidden command: {executable}\n")
        sys.exit(1)

    # 3. Sanitize the repository path
    # Git paths are usually wrapped in single quotes. We extract the path 
    # and ensure it doesn't contain malicious patterns like '../'
    if len(parts) > 1:
        repo_path = parts[1].strip("'\"")

        # Prevent Directory Traversal (e.g., ../../../etc/passwd)
        if ".." in repo_path or repo_path.startswith("/"):
            sys.stderr.write("Invalid repository path.\n")
            sys.exit(1)

        # Ensure the path only contains allowed characters (alphanumeric, -, _, .)
        if not re.match(r"^[a-zA-Z0-9\._\-/]+$", repo_path):
            sys.stderr.write("Malicious characters detected in repository path.\n")
            sys.exit(1)

    # 4. Final handoff to git-shell
    # We pass the original_cmd string to git-shell -c. 
    # git-shell itself provides a second layer of defense.
    os.execv("/usr/bin/git-shell", ["git-shell", "-c", original_cmd])


def main():
    logging.info("New SSH connection - epoch: {}".format(epoch))

    for env in os.environ:
        logging.debug("Environment: {} -- {}".format(env, os.environ[env]))

    # Get authenciated user information
    info = get_cert_info()
    if info:
        logging.info("SSH Certificate Information: Key_ID [{}] - Serial [{}] - Principals [{}]".format(info['key_id'], info['serial'], info['principals']))
    else:
        logging.info("Certificate information missing")
        sys.stderr.write("Unexpected Error")
        exit(1)

    if 'SSH_ORIGINAL_COMMAND' not in os.environ:
        logging.info("Successful login - DENYING shell access")
        sys.stderr.write("Hello! You have successfully authenticated, but we do not provide shell access.\n")
        exit(1)
    else:
        sanitize_and_execute(os.environ['SSH_ORIGINAL_COMMAND'], info)
#        os.system("{}".format(os.environ['SSH_ORIGINAL_COMMAND']))



if __name__ == "__main__":
    main()
