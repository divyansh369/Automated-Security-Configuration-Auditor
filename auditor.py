import subprocess,json,socket,datetime,os
from templates.report_template import generate_html_report

report_folder = "Reports"

def check_file_permissions(file_path,expected_permissions):
    """Check the permissions of a file with better error handling."""
    
    result = subprocess.run(["stat","-c","%a",f"{file_path}"], capture_output=True, text=True)
    permissions = result.stdout.strip()
    return permissions in expected_permissions, permissions

def check_config(search_string, file_path, expected_comparison, operator):
    try:
        result = subprocess.run(
            ["grep", search_string, file_path],
            capture_output=True,
            text=True,
            check=True
        )
        config_value = result.stdout.split()[1]
        try:
            if config_value.lower() == "no" or config_value.lower() == "yes":
                if operator == "equal":
                    return (config_value.lower() == expected_comparison.lower()), config_value
                else:
                    return False, f"Operator {operator} not supported for string comparison."
            numeric_value = int(config_value)
            if operator == "max":
                return numeric_value <= expected_comparison, numeric_value
            elif operator == "min":
                return numeric_value >= expected_comparison, numeric_value
            elif operator == "equal":
                return numeric_value == expected_comparison, numeric_value
            else:
                return False, f"Unknown operator: {operator}"
        except ValueError:
            return False, f"Non-numeric value found for {search_string}: {config_value}"

    except FileNotFoundError:
        return False, f"{file_path} not found."
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return False, f"{search_string} not found in {file_path}."
        else:
            return False, f"Grep failed with return code {e.returncode}: {e}"

def run_security_checks():
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
            status,value = check_file_permissions(check["file"],check["expected"])
        elif check["type"] == "config_value":
            status,value = check_config(
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
        "Machine": subprocess.run(["grep", "^NAME=", "/etc/os-release"], capture_output=True, text=True).stdout.split("=")[1].strip().strip('"'),
        "result": results
    }
    full_path = os.path.join(report_folder, 'security_audit_report.json')   
    with open(full_path,"w") as f:
        json.dump(report_metadata,f,indent=2)

    return results

if __name__ == "__main__":
    result = run_security_checks()
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

    generate_html_report(report_data['result'],report_data['host'],report_data['timestamp'],report_data['Machine'])