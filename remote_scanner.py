import os
import json
import datetime
import socket
import paramiko
import dotenv
import shlex
from templates.report_template import generate_html_report

dotenv.load_dotenv()

Hostname = os.environ.get("Hostname")
username = os.environ.get("username")
password = os.environ.get("password")

def run_command(client:paramiko.SSHClient, cmd:str,timeout:int=10):
    """
    Executes a command on the remote host with Paramiko and returns (exit_code, stdout, stderr).
    """
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    exit_status = stdout.channel.recv_exit_status()  # blocks until command finishes
    out = stdout.read().decode(errors="ignore").strip()
    err = stderr.read().decode(errors="ignore").strip()
    return exit_status, out, err

def is_safe_path(p: str):
    # disallow characters that would allow command chaining/injection
    forbidden = [';', '&', '|', '`', '$(', '$', '>', '<']
    return all(ch not in p for ch in forbidden)

def is_safe_token(t: str):
    # used for search tokens; allow alnum and a few common punctuation characters
    forbidden = [';', '&', '|', '`', '$(', '$', '>', '<']
    return all(ch not in t for ch in forbidden)

def test_ssh_connection():
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(Hostname, 22, username, password)

        # Connect
        print(f"Connecting to {Hostname}...")
        
        stdin,stdout,stderr = client.exec_command("whoami")
        output = stdout.read().decode().strip()
        print(f"Command Output: {output}")
        print("\n========= ✅SSH Connection Successful =============\n")
        return client
        
    except Exception as e:
        print(f"❌SSH Connection Failed: {e}")

def check_file_permissions(client, file_path, expected_permissions):
    """
    Returns (bool, actual_permissions_or_error)
    """
    if not is_safe_path(file_path):
        return False, "unsafe file path"
    cmd = f"stat -c '%a' {shlex.quote(file_path)}"
    exit_code, out, err = run_command(client, cmd)
    if exit_code != 0:
        # file may not exist or stat failed
        return False, err or f"stat failed with exit {exit_code}"
    # out contains numeric permission like 600 or 644
    return out in expected_permissions, out

def check_config(client, search_string, file_path, expected_comparison, operator):
    """
    Robustly find the config line (ignores commented lines) and extract value.
    Supports operators: 'max', 'min', 'equal' for numeric comparison and 'equal' for strings like 'no'/'yes'.
    Returns (bool, value_or_error)
    """
    if not (is_safe_token(search_string) and is_safe_path(file_path)):
        return False, "unsafe input"
    # strip leading ^ if provided
    pattern = search_string.lstrip('^')
    # awk pattern: match lines starting with optional spaces then the token, that are not commented
    # and print the second field (after whitespace or =). This handles "KEY VALUE" and "KEY=VALUE"
    awk_cmd = (
        "awk "
        f"'/^[ \\t]*{pattern}[ \\t]*[= ]/ && $1 !~ /^#/ {{ "
        "line=$0; gsub(/^[ \\t]+/,\"\",line); "
        "gsub(/\\s+#.*$/,\"\",line); "  # remove end-of-line comments starting with '#'
        "gsub(/^[^=]*=[ \\t]*/,\"\",line); "  # remove everything up to '=' if present
        "split(line, a, /[ \\t=]+/); print a[2] ? a[2] : a[1]; exit }' "
        f"{shlex.quote(file_path)}"
    )
    exit_code, out, err = run_command(client, awk_cmd)
    if exit_code != 0 or not out:
        # fallback: try grep (less robust) to provide helpful error message
        grep_cmd = f"grep -E '^[ \\t]*{pattern}' {shlex.quote(file_path)} || true"
        _, g_out, g_err = run_command(client, grep_cmd)
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

def run_security_checks(client):
    """Run all security checks and return formatted results."""

    CHECKS = [
        {"name":"Shadow File Permissions","type":"file_permission","file":"/etc/shadow","expected": ["640","600"]},
        {"name":"SSH MaxAuthTries","type":"config_value","file":"/etc/ssh/sshd_config","search_string":"MaxAuthTries","expected": 4,"operator":"max"},
        {"name":"Password Maximum Days","type":"config_value","file":"/etc/login.defs","search_string":"^PASS_MAX_DAYS","expected": 90,"operator":"max"},
        {"name":"Password Minimum Days","type":"config_value","file":"/etc/login.defs","search_string":"^PASS_MIN_DAYS", "expected": 1,"operator":"min"},
        {"name":"Password Warning Age","type":"config_value","file":"/etc/login.defs","search_string":"^PASS_WARN_AGE", "expected": 7,"operator":"min"},
        {
            "name": "SSH Root Login Disabled",
            "type": "config_value",  # NEW type - checking for string, not number
            "file": "/etc/ssh/sshd_config",
            "search_string": "^PermitRootLogin",
            "expected": "no",
            "operator": "equal"
        },
        {"name":"Passwd File Permissions","type":"file_permission","file":"/etc/passwd","expected":["644"]},
        {"name":"Group File Permissions","type":"file_permission","file":"/etc/group","expected":["644"]},
        {"name":"SSH Empty Passwords Disabled","type":"config_value","file":"/etc/ssh/sshd_config","search_string":"^PermitEmptyPasswords","expected":"no","operator":"equal"},
        {"name":"Password Minimum Length","type":"config_value","file":"/etc/login.defs","search_string":"^PASS_MIN_LEN","expected":14,"operator":"min"}

    ]

    results = []
    for check in CHECKS:
        if check["type"] == "file_permission":
            status,value = check_file_permissions(client,check["file"],check["expected"])
        elif check["type"] == "config_value":
            status,value = check_config(
                client,
                check["search_string"],
                check["file"],
                check["expected"],
                check["operator"]
            )
        results.append({
            "name":check["name"],
            "status":"PASS" if status else "FAIL",
            "expected":check["expected"],
            "actual_value":value,
        })

    report_metadata = {
        "timestamp": datetime.datetime.now().isoformat(),
        "tool": "Automated Security Compliance Script",
        "host": socket.gethostname(),
        "Machine": client.exec_command("uname")[1].read().decode().strip(),
        "result": results,
        "ip": client.exec_command('hostname -I')[1].read().decode().strip()
    }
    with open("security_audit_report.json","w") as f:
        json.dump(report_metadata,f,indent=2)

    return results

if __name__=="__main__":
    client = test_ssh_connection()

    if client:
        result = run_security_checks(client)
        for r in result:
            status = "✅ PASS" if r["status"]=="PASS" else "❌ FAIL"
            print(f"{r['name']:<30} {status} (Actual: {r['actual_value']}, Expected: {r['expected']})")

        pass_cnt = sum(1 for r in result if r["status"] == "PASS")
        fail_cnt = sum(1 for r in result if r["status"] == "FAIL")
        total_checks = len(result)
        compliance_score = (pass_cnt / total_checks) * 100 if total_checks > 0 else 0
        print("="*50)
        print(f"SUMMARY: {pass_cnt} Passed, {fail_cnt} Failed")
        print(f"COMPLIANCE SCORE: {compliance_score:.1f}%")
        print("="*50)

        # Generate HTML report
        with open("security_audit_report.json","r") as f:
            report_data = json.load(f)

        generate_html_report(report_data['result'],report_data['host'],report_data['timestamp'],report_data['Machine'],report_data['ip'])
        
        transport = client.get_transport()
        if transport and transport.is_active():
            client.close()
            print("\n✅ SSH connection closed.")
