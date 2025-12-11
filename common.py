import os
import shutil
import datetime
import json
import pathlib
import shlex
import socket
import paramiko, sys


class Utils:

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.client = None

    def create_ssh_connection(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.hostname, 22, self.username, self.password)

            print(f"Connecting to {self.hostname}...")

            stdin, stdout, stderr = self.client.exec_command("whoami")
            output = stdout.read().decode().strip()
            print(f"Command Output: {output}")
            print(
                f"\n========= ✅SSH Connection Successful {self.hostname} =============\n"
            )
            return self.client

        except (paramiko.SSHException, socket.error, OSError) as exc:
            print(f"SSH connect failed for {self.hostname}: {exc}")
            return None

    def execute_command(self, client: str, command: str, timeout: int = 10):
        stdin, stdout, stderr = self.client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()  # blocks until command finishes
        out = stdout.read().decode(errors="ignore").strip()
        err = stderr.read().decode(errors="ignore").strip()
        return exit_status, out, err

    def check_file_permissions(self, client, file_path, expected_permissions):
        """
        Returns (bool, actual_permissions_or_error)
        """
        cmd = f"stat -c '%a' {shlex.quote(file_path)}"
        exit_code, out, err = self.execute_command(client, cmd)
        if exit_code != 0:
            # file may not exist or stat failed
            return False, err or f"stat failed with exit {exit_code}"
        # out contains numeric permission like 600 or 644
        return out in expected_permissions, out

    def check_config(
        self, client, search_string, file_path, expected_comparison, operator
    ):
        """
        Robustly find the config line (ignores commented lines) and extract value.
        Supports operators: 'max', 'min', 'equal' for numeric comparison and 'equal' for strings like 'no'/'yes'.
        Returns (bool, value_or_error)
        """
        # strip leading ^ if provided
        pattern = search_string.lstrip("^")
        # awk pattern: match lines starting with optional spaces then the token, that are not commented
        # and print the second field (after whitespace or =). This handles "KEY VALUE" and "KEY=VALUE"
        awk_cmd = (
            "awk "
            f"'/^[ \\t]*{pattern}[ \\t]*[= ]/ && $1 !~ /^#/ {{ "
            'line=$0; gsub(/^[ \\t]+/,"",line); '
            'gsub(/\\s+#.*$/,"",line); '  # remove end-of-line comments starting with '#'
            'gsub(/^[^=]*=[ \\t]*/,"",line); '  # remove everything up to '=' if present
            "split(line, a, /[ \\t=]+/); print a[2] ? a[2] : a[1]; exit }' "
            f"{shlex.quote(file_path)}"
        )
        exit_code, out, err = self.execute_command(client, awk_cmd)
        if exit_code != 0 or not out:
            # fallback: try grep (less robust) to provide helpful error message
            grep_cmd = f"grep -E '^[ \\t]*{pattern}' {shlex.quote(file_path)} || true"
            _, g_out, g_err = self.execute_command(client, grep_cmd)
            if not g_out:
                return False, f"{pattern} not found in {file_path}"
            # if grep found something but awk failed to extract, return that raw line for debugging
            return False, f"unparsable line: {g_out.splitlines()[0][:200]}"
        value = out.strip()
        # normalize common boolean strings
        low = value.lower()
        if operator == "equal" and isinstance(expected_comparison, str):
            return low == str(expected_comparison).lower(), value
        # numeric comparisons
        try:
            numeric_value = int(value)
        except ValueError:
            return False, f"non-numeric value: {value}"
        if operator == "max":
            return numeric_value <= expected_comparison, numeric_value
        elif operator == "min":
            return numeric_value >= expected_comparison, numeric_value
        elif operator == "equal":
            return numeric_value == expected_comparison, numeric_value
        else:
            return False, f"unknown operator {operator}"

    def run_security_checks(self, client, report_folder):
        """Run all security checks and return formatted results."""

        CHECKS = [
            {
                "name": "Shadow File Permissions",
                "type": "file_permission",
                "file": "/etc/shadow",
                "expected": ["640", "600"],
            },
            {
                "name": "SSH MaxAuthTries",
                "type": "config_value",
                "file": "/etc/ssh/sshd_config",
                "search_string": "MaxAuthTries",
                "expected": 4,
                "operator": "max",
            },
            {
                "name": "Password Maximum Days",
                "type": "config_value",
                "file": "/etc/login.defs",
                "search_string": "^PASS_MAX_DAYS",
                "expected": 90,
                "operator": "max",
            },
            {
                "name": "Password Minimum Days",
                "type": "config_value",
                "file": "/etc/login.defs",
                "search_string": "^PASS_MIN_DAYS",
                "expected": 1,
                "operator": "min",
            },
            {
                "name": "Password Warning Age",
                "type": "config_value",
                "file": "/etc/login.defs",
                "search_string": "^PASS_WARN_AGE",
                "expected": 7,
                "operator": "min",
            },
            {
                "name": "SSH Root Login Disabled",
                "type": "config_value",  # NEW type - checking for string, not number
                "file": "/etc/ssh/sshd_config",
                "search_string": "^PermitRootLogin",
                "expected": "no",
                "operator": "equal",
            },
            {
                "name": "Passwd File Permissions",
                "type": "file_permission",
                "file": "/etc/passwd",
                "expected": ["644"],
            },
            {
                "name": "Group File Permissions",
                "type": "file_permission",
                "file": "/etc/group",
                "expected": ["644"],
            },
            {
                "name": "SSH Empty Passwords Disabled",
                "type": "config_value",
                "file": "/etc/ssh/sshd_config",
                "search_string": "^PermitEmptyPasswords",
                "expected": "no",
                "operator": "equal",
            },
            {
                "name": "Password Minimum Length",
                "type": "config_value",
                "file": "/etc/login.defs",
                "search_string": "^PASS_MIN_LEN",
                "expected": 14,
                "operator": "min",
            },
        ]

        results = []
        for check in CHECKS:
            if check["type"] == "file_permission":
                status, value = self.check_file_permissions(
                    client, check["file"], check["expected"]
                )
            elif check["type"] == "config_value":
                status, value = self.check_config(
                    client,
                    check["search_string"],
                    check["file"],
                    check["expected"],
                    check["operator"],
                )
            results.append(
                {
                    "name": check["name"],
                    "status": "PASS" if status else "FAIL",
                    "expected": check["expected"],
                    "actual_value": value,
                }
            )

        report_metadata = {
            "timestamp": datetime.datetime.now().isoformat(),
            "tool": "Automated Security Compliance Script",
            "host": socket.gethostname(),
            "Machine": client.exec_command("uname")[1].read().decode().strip(),
            "result": results,
            "ip": client.exec_command("hostname -I")[1].read().decode().strip(),
        }

        filename = (
            f"security_audit_report_{report_metadata['ip'].replace('.','_')}.json"
        )
        file_path = pathlib.Path(report_folder) / filename
        with open(file_path, "w") as f:
            json.dump(report_metadata, f, indent=2)

        return results

    """ when we use standalone function that not requires class instance then we use @staticmethod decorator"""

    @staticmethod
    def rotate_reports():
        """
        :timestamp
        :
        """
        report_dir = "Reports"
        backup_dir = os.path.join(report_dir, "Backup")

        os.makedirs(report_dir, exist_ok=True)
        os.makedirs(backup_dir, exist_ok=True)

        old_files = [
            file
            for file in os.listdir(report_dir)
            if file.endswith(".json") or file.endswith(".html")
        ]

        if not old_files:
            return

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_folder = os.path.join(backup_dir, f"backup_{timestamp}")
        os.makedirs(backup_folder, exist_ok=True)

        for file in old_files:
            src_path = os.path.join(report_dir, file)
            dst_path = os.path.join(backup_folder, file)
            shutil.move(src_path, dst_path)
