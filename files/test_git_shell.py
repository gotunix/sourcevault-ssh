# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 GOTUNIX Networks <code@gotunix.net>
# SPDX-FileCopyrightText: 2026 Justin Ovens <code@gotunix.net>
# ----------------------------------------------------------------------------------------------- #
#                          #####  ####### ####### #     # #     # ### #     #                     #
#                         #     # #     #    #    #     # ##    #  #   #   #                      #
#                         #       #     #    #    #     # # #   #  #    # #                       #
#                         #  #### #     #    #    #     # #  #  #  #     #                        #
#                         #     # #     #    #    #     # #   # #  #    # #                       #
#                         #     # #     #    #    #     # #    ##  #   #   #                      #
#                          #####  #######    #     #####  #     # ### #     #                     #
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

import unittest
import sys
import os
import shutil
import tempfile
import importlib.util
import logging
from io import StringIO
from unittest.mock import MagicMock, patch, MagicMock

# Import the module to test.
# Since it's in a specific directory, we might need to mess with sys.path or import by path.
sys.path.append("/home/jovens/code/docker/ssh/files")
import importlib.util
spec = importlib.util.spec_from_file_location("git_shell", "/home/jovens/code/docker/ssh/files/git-shell.py")
fixed_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixed_script)
sys.modules["fixed_script"] = fixed_script

class TestGitShell(unittest.TestCase):

    def test_sanitize_git_command_valid(self):
        cmd = "git-upload-pack 'repo.git'"
        exe, path = fixed_script.sanitize_git_command(cmd)
        self.assertEqual(exe, "git-upload-pack")
        self.assertEqual(path, "repo.git")

    def test_sanitize_git_command_invalid_binary(self):
        cmd = "git-fake 'repo.git'"
        # We expect sys.exit(1)
        with self.assertRaises(SystemExit) as cm:
            fixed_script.sanitize_git_command(cmd)
        self.assertEqual(cm.exception.code, 1)

    def test_sanitize_git_command_path_traversal(self):
        cmd = "git-upload-pack '../etc/passwd'"
        with self.assertRaises(SystemExit) as cm:
            fixed_script.sanitize_git_command(cmd)
        self.assertEqual(cm.exception.code, 1)

    def test_sanitize_git_command_absolute_path(self):
        cmd = "git-upload-pack '/etc/passwd'"
        with self.assertRaises(SystemExit) as cm:
            fixed_script.sanitize_git_command(cmd)
        self.assertEqual(cm.exception.code, 1)

    def test_sanitize_git_command_bad_chars(self):
        cmd = "git-upload-pack 'repo;rm -rf /'"
        with self.assertRaises(SystemExit) as cm:
            fixed_script.sanitize_git_command(cmd)
        self.assertEqual(cm.exception.code, 1)

    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.tempfile.NamedTemporaryFile')
    def test_get_cert_info(self, mock_temp, mock_run):
        # Setup Environment
        os.environ["SSH_USER_AUTH"] = "/tmp/fake_auth_file"
        
        # Mock file operations
        mock_f = MagicMock()
        mock_temp.return_value.__enter__.return_value = mock_f
        mock_f.name = "/tmp/random_temp_file"

        # Mock SSH Output
        ssh_output = """Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public Key: RSA-CERT SHA256:xyz
        Signing CA: RSA SHA256:abc
        Key ID: "test_user"
        Serial: 12345
        Valid: from 2023-01-01 to 2024-01-01
        Principals: 
                project-alpha
                team-beta
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
        """
        mock_run.return_value.stdout = ssh_output
        
        # Create a fake auth file to read
        with open("/tmp/fake_auth_file", "w") as f:
            f.write("publickey ssh-rsa-cert...")

        try:
            info = fixed_script.get_cert_info()
            self.assertEqual(info['key_id'], "test_user")
            self.assertEqual(info['serial'], "12345")
            self.assertIn("project-alpha", info['principals'])
            self.assertIn("team-beta", info['principals'])
        finally:
            if os.path.exists("/tmp/fake_auth_file"):
                os.remove("/tmp/fake_auth_file")

    def test_check_authorization(self):
        # 1. Org Scope: "org-myorg" allows any repo under "myorg/"
        principals_org = ["org-myorg"]
        self.assertTrue(fixed_script.check_authorization(principals_org, "myorg/repo.git"))
        self.assertTrue(fixed_script.check_authorization(principals_org, "myorg/project/repo.git"))
        self.assertFalse(fixed_script.check_authorization(principals_org, "otherorg/repo.git"))

        # 2. Project Scope: "project-myorg/proj" allows "myorg/proj/*"
        principals_proj = ["project-myorg/proj"]
        self.assertTrue(fixed_script.check_authorization(principals_proj, "myorg/proj/repo.git"))
        self.assertTrue(fixed_script.check_authorization(principals_proj, "myorg/proj/full/path.git"))
        # Should NOT match partial project match or other projects
        self.assertFalse(fixed_script.check_authorization(principals_proj, "myorg/other/repo.git"))
        self.assertFalse(fixed_script.check_authorization(principals_proj, "myorg/repo.git")) # Too shallow

        # 3. Repo Scope: "repo-myorg/proj/repo" exact match
        principals_repo = ["repo-myorg/proj/repo"]
        self.assertTrue(fixed_script.check_authorization(principals_repo, "myorg/proj/repo.git"))
        self.assertFalse(fixed_script.check_authorization(principals_repo, "myorg/proj/other.git"))
        
        # 4. Admin Access
        admin_principals = ["admin"]
        self.assertTrue(fixed_script.check_authorization(admin_principals, "any/thing.git"))

        # 5. Personal Repo Access
        # user-jovens -> users/jovens/repo.git
        principals_user = ["user-jovens"]
        self.assertTrue(fixed_script.check_authorization(principals_user, "users/jovens/repo.git", mode="read"))
        self.assertTrue(fixed_script.check_authorization(principals_user, "users/jovens/repo.git", mode="write")) # Owner is R/W
        
        # New: Test Separation for non-owners (Repo Sharing)
        # Guest User with Repo Read Principal
        principals_guest = ["repo-users/jovens/repo"]
        self.assertTrue(fixed_script.check_authorization(principals_guest, "users/jovens/repo.git", mode="read"))
        self.assertFalse(fixed_script.check_authorization(principals_guest, "users/jovens/repo.git", mode="write"))

        # Guest User with Repo Write Principal
        principals_collab = ["write-repo-users/jovens/repo"]
        self.assertTrue(fixed_script.check_authorization(principals_collab, "users/jovens/repo.git", mode="write"))
        # Should not access other users
        self.assertFalse(fixed_script.check_authorization(principals_user, "users/other/repo.git"))
        self.assertFalse(fixed_script.check_authorization(principals_user, "users/repo.git")) # Missing username component

    def test_check_authorization_write(self):
        # 1. Read principal denied write
        principals = ["org-myorg"]
        self.assertTrue(fixed_script.check_authorization(principals, "myorg/repo.git", mode="read"))
        self.assertFalse(fixed_script.check_authorization(principals, "myorg/repo.git", mode="write"))

        # 2. Write principal allowed write
        principals_w = ["write-org-myorg"]
        self.assertTrue(fixed_script.check_authorization(principals_w, "myorg/repo.git", mode="write"))
        self.assertTrue(fixed_script.check_authorization(principals_w, "myorg/repo.git", mode="read"))

        # 3. Project write
        principals_p = ["write-project-myorg/proj"]
        self.assertTrue(fixed_script.check_authorization(principals_p, "myorg/proj/repo.git", mode="write"))
        
        # 4. Repo write
        principals_r = ["write-repo-myorg/repo"]
        self.assertTrue(fixed_script.check_authorization(principals_r, "myorg/repo.git", mode="write"))

        # 5. User Reported Scenario: principal 'repo-gotunix/ansible' writing to 'gotunix/ansible.git'
        # Should be DENIED (Read-only principal)
        principals_reported = ["repo-gotunix/ansible"]
        self.assertTrue(fixed_script.check_authorization(principals_reported, "gotunix/ansible.git", mode="read"))
        self.assertFalse(fixed_script.check_authorization(principals_reported, "gotunix/ansible.git", mode="write"))

    @patch('fixed_script.os.execv')
    @patch('fixed_script.get_cert_info')
    @patch('fixed_script.check_authorization')
    def test_main_execution(self, mock_check, mock_get_info, mock_execv):
        # Setup
        # We need to simulate SSH environment variables
        os.environ["SSH_USER_AUTH"] = "/tmp/fake_auth"
        os.environ["SSH_ORIGINAL_COMMAND"] = "git-upload-pack 'org/repo.git'"
        
        # Mock get_cert_info to return authorized principals
        mock_get_info.return_value = {
            "key_id": "user", 
            "serial": "123", 
            "principals": ["org-org"]
        }
        mock_check.return_value = True
        
        # Run main
        fixed_script.main()
        
        # Verify
        mock_check.assert_called_with(["org-org"], "org/repo.git", mode="read")
        
        # Expected: git-shell -c "git-upload-pack '/data/git/orginizations/org/repo.git'"
        expected_cmd = "git-upload-pack '/data/git/orginizations/org/repo.git'"
        mock_execv.assert_called_with("/usr/bin/git-shell", ["git-shell", "-c", expected_cmd])

    @patch('fixed_script.os.execv')
    @patch('fixed_script.get_cert_info')
    @patch('fixed_script.check_authorization')
    def test_main_execution_write(self, mock_check, mock_get_info, mock_execv):
        # Setup
        os.environ["SSH_USER_AUTH"] = "/tmp/fake_auth"
        os.environ["SSH_ORIGINAL_COMMAND"] = "git-receive-pack 'org/repo.git'"
        
        mock_get_info.return_value = {"key_id": "user", "serial": "1", "principals": ["write-org-org"]}
        mock_check.return_value = True
        
        # Update expected_cmd to reflect REPO_ROOT change
        expected_cmd = "git-receive-pack '/data/git/orginizations/org/repo.git'"
        
        # Act
        fixed_script.main()
        
        # Verify
        mock_check.assert_called_with(["write-org-org"], "org/repo.git", mode="write")
        
        # Assert
        # Check that we constructed the write command
        # Note: os.execv arguments: path, args list
        mock_execv.assert_called_with("/usr/bin/git-shell", ["git-shell", "-c", expected_cmd])

    @patch('fixed_script.os.execv')
    @patch('fixed_script.get_cert_info')
    @patch('fixed_script.check_authorization')
    def test_main_execution_users(self, mock_check, mock_get_info, mock_execv):
        # Setup for personal repo
        os.environ["SSH_USER_AUTH"] = "/tmp/fake_auth"
        os.environ["SSH_ORIGINAL_COMMAND"] = "git-receive-pack 'users/jovens/repo.git'"
        
        # Owner "user-jovens" now implies Write access again
        mock_get_info.return_value = {"key_id": "u", "serial": "1", "principals": ["user-jovens"]}
        mock_check.return_value = True
        
        # Update expected_cmd to reflect REPO_ROOT change
        expected_cmd = "git-receive-pack '/data/git/users/jovens/repo.git'"
        
        fixed_script.main()
        
        # Verify
        mock_check.assert_called_with(["user-jovens"], "users/jovens/repo.git", mode="write")
        
        # Expected: /git/users/... (NO orginizations prefix)
        mock_execv.assert_called_with("/usr/bin/git-shell", ["git-shell", "-c", expected_cmd])

    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.os.makedirs')
    def test_create_bare_repo(self, mock_makedirs, mock_run):
        fixed_script.create_bare_repo("/git/new/repo.git")
        mock_makedirs.assert_called_with("/git/new/repo.git", exist_ok=True)
        mock_run.assert_called_with(["git", "init", "--bare", "/git/new/repo.git"], check=True, capture_output=True)

    @patch('fixed_script.subprocess.run') # Added patch for subprocess.run
    @patch('fixed_script.create_bare_repo')
    @patch('fixed_script.get_input')
    @patch('sys.exit')
    def test_interactive_menu_personal(self, mock_exit, mock_input, mock_create, mock_run): # Added mock_run to args
        # Principals
        principals = ["user-jovens"]
        key_id = "jovens"
        
        # Inputs: 
        # 1. "1" (Personal)
        # 2. "newrepo" (Repo Name)
        # 3. "8" (Exit)
        mock_input.side_effect = ["1", "newrepo", "8"]
        
        with patch("fixed_script.REPO_ROOT", "/data/git"): # Changed to /data/git
            fixed_script.interactive_menu(principals, key_id)
            
            # Verify creation was called with NEW ROOT
            # Rel path: users/jovens/newrepo.git
            # Abs path: /data/git/users/jovens/newrepo.git
            mock_create.assert_called_with("/data/git/users/jovens/newrepo.git")

    @patch('fixed_script.create_bare_repo')
    @patch('fixed_script.get_input')
    @patch('sys.exit')
    def test_interactive_menu_org_denied(self, mock_exit, mock_input, mock_create):
        # Principals (READ ONLY for org) - should be DENIED creation
        principals = ["org-myorg"] 
        key_id = "jovens"

        # Inputs:
        # 1. "2" (Org)
        # 2. "myorg" (Org Name)
        # 3. "" (Proj Name - Skip)
        # 4. "newrepo" (Repo Name)
        # 5. "8" (Exit)
        mock_input.side_effect = ["2", "myorg", "", "newrepo", "8"]
        
        fixed_script.interactive_menu(principals, key_id)
        
        # Verify creation was NOT called
        mock_create.assert_not_called()

    @patch('fixed_script.create_bare_repo')
    @patch('fixed_script.get_input')
    @patch('sys.exit')
    def test_interactive_menu_org_allowed(self, mock_exit, mock_input, mock_create):
        # Principals (WRITE for org)
        principals = ["write-org-myorg"] 
        key_id = "jovens"

        # Inputs:
        # 1. "2" (Org)
        # 2. "myorg" (Org Name)
        # 3. "myproj" (Proj Name)
        # 4. "newrepo" (Repo Name)
        # 5. "8" (Exit)
        mock_input.side_effect = ["2", "myorg", "myproj", "newrepo", "8"]
        
        fixed_script.interactive_menu(principals, key_id)
        
        # Verify creation WAS called
        # Abs path: /git/orginizations/myorg/myproj/newrepo.git
        mock_create.assert_called_with(os.path.join(fixed_script.REPO_ROOT, "orginizations", "myorg", "myproj", "newrepo.git"))

    @patch('fixed_script.interactive_menu')
    @patch('fixed_script.get_cert_info')
    @patch('sys.exit')
    @patch('fixed_script.os.execv')
    def test_main_no_command_authorized(self, mock_execv, mock_exit, mock_get_info, mock_menu):
        # If SSH_ORIGINAL_COMMAND is missing
        if "SSH_ORIGINAL_COMMAND" in os.environ:
            del os.environ["SSH_ORIGINAL_COMMAND"]
        os.environ["SSH_USER_AUTH"] = "/tmp/fake"
        
        # User HAS "interactive" principal
        mock_get_info.return_value = {"key_id": "u", "serial": "1", "principals": ["interactive", "user-u"]}
        
        fixed_script.main()
        
        mock_menu.assert_called_with(["interactive", "user-u"], "u")
        # Ensure we exited cleanly
        mock_exit.assert_called_with(0)

    @patch('fixed_script.interactive_menu')
    @patch('fixed_script.get_cert_info')
    @patch('sys.exit')
    @patch('fixed_script.os.execv')
    def test_main_no_command_denied(self, mock_execv, mock_exit, mock_get_info, mock_menu):
        # If SSH_ORIGINAL_COMMAND is missing
        if "SSH_ORIGINAL_COMMAND" in os.environ:
            del os.environ["SSH_ORIGINAL_COMMAND"]
        os.environ["SSH_USER_AUTH"] = "/tmp/fake"
        
        # User MISSING "interactive" principal
        mock_get_info.return_value = {"key_id": "u", "serial": "1", "principals": ["user-u"]}
        
        # This will call sys.exit(1), which is patched
        fixed_script.main()
            
        mock_menu.assert_not_called()
        mock_exit.assert_called_with(1)

    @patch('builtins.print')
    @patch('fixed_script.os.walk')
    @patch('fixed_script.os.path.exists')
    @patch('fixed_script.check_authorization')
    def test_list_repos(self, mock_check, mock_exists, mock_walk, mock_print):
        mock_exists.return_value = True
        mock_check.return_value = True
        # Mock file structure:
        # /git/orginizations/myorg/repo.git
        # /git/users/jovens/repo.git
        # Mock walk: /data/git/orginizations/myorg/repo.git
        mock_walk.return_value = [
            ("/data/git/orginizations/myorg", ["repo.git"], []),
            ("/data/git/orginizations/myorg/repo.git", ["refs", "objects"], [])
        ]
        
        
        # Scenario: User has access to myorg/repo.git but not others
        principals = ["org-myorg"]
        
        
        with patch("fixed_script.REPO_ROOT", "/data/git"):
             fixed_script.list_repos(principals)
        
        # Verify print calls
        found = False
        for call in mock_print.call_args_list:
            # call is (args, kwargs)
            # args[0] is the string printed
            if call[0] and "myorg/repo.git" in str(call[0][0]):
                 found = True
        self.assertTrue(found, "Should list authorized repo")

    @patch('fixed_script.shutil.rmtree')
    @patch('fixed_script.get_input')
    @patch('fixed_script.os.path.exists')
    def test_delete_repo_authorized(self, mock_exists, mock_input, mock_rmtree):
        mock_exists.return_value = True
        principals = ["write-org-myorg"]
        
        # Inputs: "myorg/repo.git", "yes"
        mock_input.side_effect = ["myorg/repo.git", "yes"]
        
        fixed_script.delete_repo(principals)
        
        mock_rmtree.assert_called_with("/data/git/orginizations/myorg/repo.git")

    @patch('fixed_script.shutil.rmtree')
    @patch('fixed_script.get_input')
    @patch('fixed_script.os.path.exists')
    def test_delete_repo_denied(self, mock_exists, mock_input, mock_rmtree):
        mock_exists.return_value = True
        # Read only
        principals = ["org-myorg"]
        
        # Inputs: "myorg/repo.git"
        mock_input.side_effect = ["myorg/repo.git"]
        
        fixed_script.delete_repo(principals)
        
        mock_rmtree.assert_not_called()

    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.get_input')
    @patch('fixed_script.os.path.exists')
    def test_view_readme_success(self, mock_exists, mock_input, mock_run):
        mock_exists.return_value = True
        principals = ["org-myorg"] # Read access is enough
        
        # Inputs: "myorg/repo.git", "main" (Branch)
        mock_input.side_effect = ["myorg/repo.git", "main"]
        
        # Mock success output
        mock_run.return_value.stdout = "# My Readme Content"
        
        fixed_script.view_readme(principals)
        
        # Verify git show command
        # path construction depends on REPO_ROOT, assumes /git by default in test unless patched
        # Since we didn't patch REPO_ROOT here, check if it behaves as default (/git)
        # But wait, REPO_ROOT is evaluated at import.
        
        # Let's inspect call args to be safe or patch REPO_ROOT?
        # Assuming defaults: /git/orginizations/myorg/repo.git
        
        args, kwargs = mock_run.call_args
        cmd = args[0]
        self.assertIn("git", cmd)
        self.assertIn("show", cmd)
        self.assertIn("main:README.md", cmd)

    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.get_input')
    @patch('fixed_script.os.path.exists')
    def test_view_readme_denied(self, mock_exists, mock_input, mock_run):
        mock_exists.return_value = True
        principals = ["org-other"] # No access
        
        # Inputs: "myorg/repo.git"
        mock_input.side_effect = ["myorg/repo.git"]
        
        fixed_script.view_readme(principals)
        
        mock_run.assert_not_called()


    @patch('builtins.print')
    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.get_input')
    @patch('fixed_script.os.path.exists')
    def test_view_history_success(self, mock_exists, mock_input, mock_run, mock_print):
        mock_exists.return_value = True
        principals = ["org-myorg"]
        
        # Inputs: "myorg/repo.git", "main", "5"
        mock_input.side_effect = ["myorg/repo.git", "main", "5"]
        
        # Mock git log with custom format output
        separator = "COMMIT_START"
        mock_output = f"""{separator}
a1b2c3d Message (Author)
gpg: Good signature from "Author <email>"
{separator}
e4f5g6h Message 2 (Author)
"""
        mock_run.return_value.stdout = mock_output
        
        fixed_script.view_history(principals)
        
        # Expected arguments
        args, _ = mock_run.call_args
        # args[0] is the command list
        self.assertEqual(args[0][0], "git")
        self.assertEqual(args[0][2], "/data/git/orginizations/myorg/repo.git")
        
        # Check format string and flag
        # self.assertIn("--show-signature", args[0]) # Should NOT be present
        expected_format = f"--pretty=format:{separator}%n%h %s (%an)%n%GG"
        self.assertIn(expected_format, args[0])
        
        # Verify output parsing
        # 1. Header and GPG
        mock_print.assert_any_call('\na1b2c3d Message (Author)')
        mock_print.assert_any_call('  gpg: Good signature from "Author <email>"')
        # 2. Unsigned
        mock_print.assert_any_call('\ne4f5g6h Message 2 (Author)')
        mock_print.assert_any_call('  No signature')

    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.get_input')
    @patch('fixed_script.os.path.exists')
    def test_view_history_denied(self, mock_exists, mock_input, mock_run):
        mock_exists.return_value = True
        principals = ["org-other"] # No access
        
        # Inputs: "myorg/repo.git"
        mock_input.side_effect = ["myorg/repo.git"]
        
        fixed_script.view_history(principals)
        
        mock_run.assert_not_called()

    @patch('logging.FileHandler')
    @patch('fixed_script.os.path.exists')
    def test_setup_logging_file_only(self, mock_exists, mock_file):
        # Ensure handlers are cleared
        logging.getLogger().handlers = []
        
        # Test Case: Only File Logging
        # exists returns True for dirname(/tmp)
        def exists_side_effect(path):
            if path == "/tmp": return True
            return False
        
        mock_exists.side_effect = exists_side_effect
        
        # Mock FileHandler
        mock_file.return_value = MagicMock()

        with patch("fixed_script.LOG_PATH", "/tmp/test.log"):
            fixed_script.setup_logging()
            
            logger = logging.getLogger()
            # Should have added 1 handler (FileHandler)
            # Should have added 1 handler (FileHandler)
            self.assertEqual(len(logger.handlers), 1)
            self.assertEqual(mock_file.call_count, 1)

    @patch('fixed_script.manage_keys')
    @patch('fixed_script.get_input')
    @patch('fixed_script.os.path.exists')
    @patch('fixed_script.ensure_server_key')
    def test_interactive_menu_manage_keys(self, mock_ensure_server, mock_exists, mock_input, mock_manage):
        mock_exists.return_value = True
        principals = ["user-jovens"]
        key_id = "jovens"
        
        # User input: "7" (Manage Keys), "8" (Exit)
        mock_input.side_effect = ["7", "8"]
        
        with patch("sys.exit") as mock_exit:
            fixed_script.interactive_menu(principals, key_id)
            
            mock_ensure_server.assert_called_once()
            mock_manage.assert_called_with(principals, key_id)
            mock_exit.assert_called_with(0)

    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.get_input')
    def test_manage_keys_list(self, mock_input, mock_run):
        # 1. List Keys, 4. Back
        mock_input.side_effect = ["1", "4"]
        
        fixed_script.manage_keys([], "user_123")
        # Call 3: check-trustdb
        args3, _ = mock_run.call_args_list[1] # check-trustdb is 1st call, list keys is 2nd? No.
        # Logic in manage_keys:
        # 1. check-trustdb
        # 2. list-keys
        args0, _ = mock_run.call_args_list[0]
        self.assertEqual(args0[0], ["gpg", "--check-trustdb"])
        args1, _ = mock_run.call_args_list[1]
        self.assertEqual(args1[0], ["gpg", "--list-keys"])

    @patch('fixed_script.load_gpg_owners')
    @patch('fixed_script.save_gpg_owners')
    @patch('fixed_script.get_fingerprint_from_block')
    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.get_input')
    def test_manage_keys_import(self, mock_input, mock_run, mock_get_fp, mock_save_owners, mock_load_owners):
        # 2. Import, KEYBLOCK, END, 4. Back
        mock_input.side_effect = ["2", "-----BEGIN PGP PUBLIC KEY BLOCK-----", "...", "END", "4"]
        
        # Mock ID detection
        mock_get_fp.return_value = "AABBCCDD12345678AABBCCDD12345678AABBCCDD"
        
        # Mock owners
        mock_load_owners.return_value = {}

        # Mock results
        import_result = MagicMock()
        import_result.returncode = 0
        import_result.stderr = "gpg: key imported"
        
        sign_result = MagicMock()
        sign_result.returncode = 0
        
        check_result = MagicMock()
        check_result.returncode = 0
        
        mock_run.side_effect = [import_result, sign_result, check_result]
        
        fixed_script.manage_keys([], "user_123")
        
        # Verify ownership saved
        mock_save_owners.assert_called()
        saved_map = mock_save_owners.call_args[0][0]
        self.assertEqual(saved_map["AABBCCDD12345678AABBCCDD12345678AABBCCDD"], "user_123")

    @patch('fixed_script.load_gpg_owners')
    @patch('fixed_script.save_gpg_owners')
    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.get_input')
    def test_manage_keys_remove_authorized(self, mock_input, mock_run, mock_save_owners, mock_load_owners):
        # 3. Remove, KEYID, 4. Back
        mock_input.side_effect = ["3", "user@example.com", "4"]
        
        # Mock resolving fingerprint from email
        list_result = MagicMock()
        list_result.returncode = 0
        # Format: fpr:::::::::FINGERPRINT:
        list_result.stdout = "fpr:::::::::AABBCCDD12345678AABBCCDD12345678AABBCCDD:"
        
        # Mock deletion
        delete_result = MagicMock()
        delete_result.returncode = 0
        
        mock_run.side_effect = [list_result, delete_result]
        
        # Mock ownership
        mock_load_owners.return_value = {"AABBCCDD12345678AABBCCDD12345678AABBCCDD": "user_123"}
        
        # User is "user_123" (Owner)
        fixed_script.manage_keys([], "user_123")
        
        # Verify delete called
        args, _ = mock_run.call_args_list[1]
        self.assertEqual(args[0], ["gpg", "--batch", "--yes", "--delete-keys", "AABBCCDD12345678AABBCCDD12345678AABBCCDD"])
        
        # Verify removed from mapping
        mock_save_owners.assert_called()
        self.assertNotIn("AABBCCDD12345678AABBCCDD12345678AABBCCDD", mock_save_owners.call_args[0][0])

    @patch('fixed_script.load_gpg_owners')
    @patch('fixed_script.subprocess.run')
    @patch('fixed_script.get_input')
    def test_manage_keys_remove_unauthorized(self, mock_input, mock_run, mock_load_owners):
        # 3. Remove, KEYID, 4. Back
        mock_input.side_effect = ["3", "user@example.com", "4"]
        
        # Mock resolving fingerprint
        list_result = MagicMock()
        list_result.returncode = 0
        list_result.stdout = "fpr:::::::::AABBCCDD12345678AABBCCDD12345678AABBCCDD:"
        
        mock_run.side_effect = [list_result]
        
        # Mock ownership (Owned by SOMEONE_ELSE)
        mock_load_owners.return_value = {"AABBCCDD12345678AABBCCDD12345678AABBCCDD": "other_user"}
        
        # User is "user_123" (Not Owner, Not Admin)
        fixed_script.manage_keys([], "user_123")
        
        # Verify delete NOT called
        self.assertEqual(mock_run.call_count, 1) # Only list-keys called

    @patch('fixed_script.subprocess.run')
    def test_get_fingerprint_from_block(self, mock_run):
        key_data = "FAKE_KEY_DATA"
        
        # Mock gpg --show-keys output
        mock_run.return_value.stdout = """
pub:-:2048:1:12345678ABCD:123456:123456::
fpr:::::::::AABBCCDD12345678AABBCCDD12345678AABBCCDD:
uid:-::::12345678ABCD::User <email@example.com>::
"""
        mock_run.return_value.returncode = 0
        
        fp = fixed_script.get_fingerprint_from_block(key_data)
        
        self.assertEqual(fp, "AABBCCDD12345678AABBCCDD12345678AABBCCDD")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0], ["gpg", "--show-keys", "--with-colons"])
        self.assertEqual(kwargs['input'], key_data)


    
    @patch('fixed_script.subprocess.run')
    def test_ensure_server_key_creates_if_missing(self, mock_run):
        # Mocks for sequential calls:
        # 1. check secret key (fails - blank stdout)
        # 2. generate key (success)
        # 3. get fingerprint (returns format)
        # 4. import ownertrust (success)
        
        # 1. check secret
        res_check = MagicMock()
        res_check.stdout = ""
        
        # 2. generate
        res_gen = MagicMock()
        res_gen.returncode = 0
        
        # 3. get fingerprint
        res_fp = MagicMock()
        res_fp.stdout = "fpr:::::::::AABBCCDD12345678:"
        
        # 4. import trust
        res_trust = MagicMock()
        res_trust.returncode = 0
        
        # 5. check trustdb
        res_check_db = MagicMock()
        res_check_db.returncode = 0
        
        mock_run.side_effect = [res_check, res_gen, res_fp, res_trust, res_check_db]
        
        fixed_script.ensure_server_key()
        
        # Verify generate called (2nd call)
        # call_args_list[1] -> call object -> args tuple -> first arg list
        args_gen = mock_run.call_args_list[1][0] 
        self.assertEqual(args_gen[0], ["gpg", "--batch", "--generate-key"])
        
        # Verify trust set (4th call)
        args_trust, kwargs_trust = mock_run.call_args_list[3]
        self.assertEqual(args_trust[0], ["gpg", "--import-ownertrust"])
        self.assertEqual(kwargs_trust['input'], "AABBCCDD12345678:6:\n")
        
        # Verify check-trustdb (5th call)
        args_check_db, _ = mock_run.call_args_list[4]
        self.assertEqual(args_check_db[0], ["gpg", "--check-trustdb"])
        
    @patch('fixed_script.subprocess.run')
    def test_ensure_server_key_skips_if_exists(self, mock_run):
        # 1. check secret key (exists)
        res_check = MagicMock()
        res_check.stdout = "sec:..."
        
        # 2. get fingerprint
        res_fp = MagicMock()
        res_fp.stdout = "fpr:::::::::AABBCCDD12345678:\n"
        
        # 3. import trust
        res_trust = MagicMock()
        res_trust.returncode = 0
        
        # 4. check trustdb
        res_check_db = MagicMock()
        res_check_db.returncode = 0
        
        mock_run.side_effect = [res_check, res_fp, res_trust, res_check_db]
        
        fixed_script.ensure_server_key()
        
        # Verify generate NOT called
        # Call 1 was check
        args_check = mock_run.call_args_list[0][0]
        self.assertIn("--list-secret-keys", args_check[0])
        
        # Verify trust still set (to ensure consistency)
        # Call 2 was fp, Call 3 was trust, Call 4 was check-trustdb
        args_trust, kwargs_trust = mock_run.call_args_list[2]
        self.assertEqual(args_trust[0], ["gpg", "--import-ownertrust"])
        self.assertEqual(kwargs_trust['input'], "AABBCCDD12345678:6:\n")
        
        # Verify check-trustdb (4th call)
        args_check_db, _ = mock_run.call_args_list[3]
        self.assertEqual(args_check_db[0], ["gpg", "--check-trustdb"])

if __name__ == '__main__':
    unittest.main()
