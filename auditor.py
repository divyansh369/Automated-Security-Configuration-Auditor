import subprocess

def check_file_permissions(file_path):
    """Check the permissions of /etc/shadow file."""
    result = subprocess.run(["stat","-c","%a",f"{file_path}"], capture_output=True, text=True)
    permissions = result.stdout.strip()
    return permissions in ["640", "600"] ,permissions

def check_config(search_string,file_path,default_value):
    """Check SSH MaxAuthTries setting."""

    try:
        result = subprocess.run(
            ["grep",search_string,file_path],
            capture_output=True,
            text=True,
            check=True
        )
        check_config = result.stdout.split()[1]
        return int(check_config) <= default_value, check_config
    except FileNotFoundError:
        return f"{file_path} file not found."
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return f"{search_string} not found in {file_path}."
        else:
            return f"Error executing grep with return code {e.returncode} : {e}"

# Run the check
print("\n========== SECURITY CHECKS ===========\n")

status,value = check_file_permissions('/etc/shadow')
print(f"Shadow Permission : {'PASS' if status else 'FAIL'} (value: {value})")

status,value = check_config(search_string="MaxAuthTries",file_path="/etc/ssh/sshd_config",default_value=4)
print(f"SSH MaxAuthTries : {'PASS' if status else 'FAIL'} (value: {value})")

status,value = check_config(search_string="^PASS_MAX_DAYS",file_path="/etc/login.defs",default_value=90)
print(f"Password Maximum Days : {'PASS' if status else 'FAIL'} (value: {value})")