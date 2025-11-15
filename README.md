# Automated Security Compliance Auditor 🔒

![Security Scanner](https://img.shields.io/badge/security-compliance%20auditor-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Level](https://img.shields.io/badge/level-2%20complete-success.svg)
![CIS](https://img.shields.io/badge/CIS-Benchmarks-orange.svg)

A Python-based automated security configuration auditor for Linux systems that evolved from basic local checks to **enterprise-ready remote scanning**. This tool checks critical security settings against CIS Benchmarks and generates comprehensive reports for DevSecOps workflows.

---

## 📖 Project Evolution

### Level 1: Foundation (Weeks 1-4) ✅
Built a local security auditor that runs on a single system with 10 core CIS benchmark checks.

**What I Built:**
- ✅ 10 automated security checks (file permissions, password policies, SSH hardening)
- ✅ JSON report generation
- ✅ Pass/fail logic with compliance scoring
- ✅ Modular, reusable functions
- ✅ Error handling for missing configs

**Technologies:** Python, subprocess, JSON, Docker/WSL testing environment

### Level 2: Production-Ready Remote Scanner (Weeks 5-8) ✅
Scaled to multi-server environments with SSH-based remote auditing and professional reporting.

**What I Added:**
- ✅ SSH-based remote server auditing (Paramiko)
- ✅ Centralized scanning from one control node
- ✅ Environment-based credential management (.env)
- ✅ Enhanced HTML reports with visual dashboards
- ✅ Compliance scoring and charts
- ✅ Production-ready error handling

**Technologies:** Paramiko (SSH), python-dotenv, Jinja2 (HTML templating), Docker networking

---

## 🚀 Key Features

### Security Auditing Capabilities
- **10 CIS Benchmark checks** covering authentication, SSH configuration, and file permissions
- **Remote scanning** - Audit servers via SSH without manual login
- **Compliance scoring** - Instant visibility (0-100%) into security posture
- **Real vulnerability detection** - Identifies weak passwords, insecure SSH, file permission issues

### Professional Reporting
- **HTML dashboard** with visual compliance charts and color-coded results
- **JSON output** for automation, CI/CD integration, and SIEM ingestion
- **Metadata tracking** - Timestamps, hostname, OS details, scan duration
- **Detailed findings** with expected vs actual values

### Enterprise-Ready Architecture
- **Environment variable management** for secure credential handling
- **Extensible design** - Easy to add custom security checks
- **Docker-compatible** - Tested in isolated container environments
- **Production error handling** - Graceful failures with detailed logging

---

## 🛡️ Security Checks Performed

| Check Name                   | File/Config              | Expected Value          | CIS Control | Severity  |
|------------------------------|--------------------------|-------------------------|-------------|-----------|
| Shadow File Permissions      | /etc/shadow              | 640 or 600              | 6.1.3       | HIGH      |
| Passwd File Permissions      | /etc/passwd              | 644                     | 6.1.2       | MEDIUM    |
| Group File Permissions       | /etc/group               | 644                     | 6.1.4       | MEDIUM    |
| SSH MaxAuthTries             | /etc/ssh/sshd_config     | ≤ 4                     | 5.2.5       | MEDIUM    |
| SSH Root Login Disabled      | /etc/ssh/sshd_config     | PermitRootLogin no      | 5.2.10      | HIGH      |
| SSH Empty Passwords Disabled | /etc/ssh/sshd_config     | PermitEmptyPasswords no | 5.2.9       | HIGH      |
| Password Maximum Days        | /etc/login.defs          | ≤ 90 days               | 5.4.1.1     | MEDIUM    |
| Password Minimum Days        | /etc/login.defs          | ≥ 1 day                 | 5.4.1.2     | MEDIUM    |
| Password Warning Age         | /etc/login.defs          | ≥ 7 days                | 5.4.1.4     | LOW       |
| Password Minimum Length      | /etc/login.defs          | ≥ 8 characters          | 5.4.1.3     | MEDIUM    |

**Why These Checks Matter:**
- **File permissions** prevent unauthorized access to sensitive password hashes
- **SSH hardening** blocks brute-force attacks and root compromise
- **Password policies** enforce strong authentication standards

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Docker (for testing environments)
- SSH access to target servers


### Quick Start

1. **Clone the repository:**
2. **Install dependencies:**


### Sample Output

```
========= ✅SSH Connection Successful =============

Shadow File Permissions ✅ PASS (Actual: 640, Expected: ['640', '600'])
Passwd File Permissions ✅ PASS (Actual: 644, Expected: ['644'])
Group File Permissions ✅ PASS (Actual: 644, Expected: ['644'])
SSH MaxAuthTries ❌ FAIL (Actual: 6, Expected: 4)
SSH Root Login Disabled ❌ FAIL (Actual: yes, Expected: no)
PermitEmptyPasswords Disabled ❌ FAIL (Actual: not configured, Expected: no)
Password Maximum Days ❌ FAIL (Actual: 99999, Expected: 90)
Password Minimum Days ❌ FAIL (Actual: 0, Expected: 1)
Password Warning Age ✅ PASS (Actual: 7, Expected: 7)
Password Minimum Length ❌ FAIL (Actual: not configured, Expected: 8)
SUMMARY: 4 Passed, 6 Failed
COMPLIANCE SCORE: 40.0%
✅ Enhanced HTML report generated!
```

### Generated Reports

**Files Created:**
- `security_audit_report.json` - Machine-readable results for automation
- `security_audit_report.html` - Visual dashboard with charts and badges

**JSON Report Structure:**
```
{
    "timestamp": "2025-11-15T23:10:00.123456",
    "tool": "Automated Security Compliance Script",
    "host": "target-server",
    "Machine": "Linux target-server 5.15.0-1 x86_64",
    "compliance_score": "40.0%",
    "summary": {
    "total": 10,
    "passed": 4,
    "failed": 6
    },
    "result": [
    {
    "name": "Shadow File Permissions",
    "status": "PASS",
    "expected": ["640", "600"],
    "actual_value": "640"
    }
    // ... more results
    ]
}
```

## 🧪 Testing with Docker

### Create Test Environment

**Terminal 1 - Create Target Server:**
Create and start target container
docker run -d --name target-server ubuntu:22.04 tail -f /dev/null

Enter the container
docker exec -it target-server bash

Inside container - setup SSH server
apt update && apt install -y openssh-server iproute2
echo 'root:test123' | chpasswd
echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
mkdir -p /var/run/sshd
service ssh start

Get IP address (copy this for .env file)
hostname -I

Output: 172.17.0.3
Exit container but leave it running
exit


**Terminal 2 - Run Auditor:**
Start your auditor container
docker start cis-test
docker exec -it cis-test bash

Update .env with target IP
Hostname=172.17.0.3
username=root
password=test123
port=22
Run the scan
python3 /app/auditor.py


---

## 🏗️ Project Architecture

````markdown
security-auditor/
├── auditor.py                      # Main scanner with SSH support (Level 2)
├── templates/
│   └── report_template.py          # HTML report generator with charts
├── .env                            # Environment variables (gitignored)
├── .gitignore                      # Excludes .env, reports, __pycache__
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── LICENSE                         # MIT License
├── security_audit_report.json     # Generated report (JSON)
└── security_audit_report.html     # Generated report (HTML)
````


### Core Components

**1. SSH Connection Manager (`auditor.py`):**
- Paramiko-based SSH client with AutoAddPolicy
- Environment variable configuration
- Timeout handling and graceful failures
- Connection pooling ready

**2. Security Check Functions:**
File permission checks
check_file_permissions(client, file_path, expected_permissions)

Config value checks (numeric + string)
check_config(client, search_string, file_path, expected, operator)


**3. Report Generator (`templates/report_template.py`):**
- HTML template with embedded CSS/JavaScript
- Compliance score visualization
- Pass/fail pie charts
- Responsive design for mobile/desktop

**4. Main Execution Flow:**
Load .env credentials

Establish SSH connection

Run all checks sequentially

Calculate compliance score

Generate JSON + HTML reports

Close SSH connection gracefully

---

## 🔧 Configuration & Customization

### Adding Custom Security Checks

**Step 1:** Add a new entry to the `CHECKS` list in `auditor.py`:

CHECKS = [
# ... existing checks ...

````markdown
# New check example: Firewall status
{
    "name": "Firewall Enabled",
    "type": "config_value",
    "file": "/usr/bin/systemctl",  # Use command output
    "search_string": "ufw",
    "expected": "active",
    "operator": "equal"
}
]
docker run -d --name target-server
````

**Step 2:** Test the check:
python3 auditor.py


### Supported Check Types

| Type              | Description                          | Operators              |
|-------------------|--------------------------------------|------------------------|
| `file_permission` | Checks UNIX permission bits          | N/A (exact match)      |
| `config_value`    | Checks numeric/string config values  | `min`, `max`, `equal`  |

### Operators Explained

- **`min`**: Actual value must be ≥ expected (e.g., password min length)
- **`max`**: Actual value must be ≤ expected (e.g., SSH max auth tries)
- **`equal`**: Actual must exactly match expected (e.g., "yes" vs "no")

---

## 📊 Sample HTML Report

The generated HTML report includes:

**Visual Elements:**
- ✅ **Compliance Badge** - Color-coded score indicator (red < 50%, yellow 50-79%, green ≥ 80%)
- 📊 **Pass/Fail Chart** - Interactive pie chart showing check distribution
- 📋 **Detailed Findings Table** - Sortable table with color-coded status
- 🕒 **Metadata Section** - Scan timestamp, target host, OS information

```
**Example Screenshot:**
╔════════════════════════════════════════╗
║ Security Audit Report ║
║ Compliance Score: 70% [🟡] ║
╠════════════════════════════════════════╣
║ Host: web-server-1 ║
║ Scanned: 2025-11-15 23:10:00 ║
║ OS: Ubuntu 22.04 LTS ║
╠════════════════════════════════════════╣
║ [Chart: 7 Passed, 3 Failed] ║
╠════════════════════════════════════════╣
║ Check Name Status Value ║
║ Shadow Permissions ✅ PASS 640 ║
║ SSH MaxAuthTries ❌ FAIL 6 ║
║ ... ║
╚════════════════════════════════════════╝
```

---

## 📈 Development Roadmap

### ✅ Completed (Levels 1-2)
- [x] Local security auditing (10 CIS checks)
- [x] JSON report generation
- [x] Modular function architecture
- [x] Remote SSH scanning with Paramiko
- [x] HTML visual reports with charts
- [x] Compliance scoring algorithm
- [x] Environment-based configuration
- [x] Docker test environment setup

### 🚧 Level 3: Advanced Features (Planned)
- [ ] **Multi-host parallel scanning** - Scan 10+ servers simultaneously with threading
- [ ] **Historical trend analysis** - Track compliance over time, detect drift
- [ ] **Scheduled automation** - Cron/systemd integration for daily scans
- [ ] **Cloud platform support** - AWS EC2, Azure VMs, GCP instances
- [ ] **Alert integration** - Email/Slack/Discord notifications on critical findings
- [ ] **REST API** - Expose scanner as microservice for CI/CD integration
- [ ] **SIEM integration** - Send findings to Splunk, ELK, or QRadar
- [ ] **Remediation scripts** - Auto-fix common misconfigurations

### 💡 Future Enhancements
- Custom check plugins (user-defined rules)
- Database storage for historical data
- Web UI dashboard for management
- Container security scanning (Docker/Kubernetes)
- Compliance frameworks (PCI-DSS, HIPAA, SOC2)

---

## 🎓 Learning Outcomes

### Technical Skills Demonstrated
- **Python automation** - subprocess, SSH, file I/O, data processing
- **Security fundamentals** - CIS Benchmarks, Linux hardening, vulnerability assessment
- **Remote administration** - SSH protocol, credential management, error handling
- **DevSecOps practices** - Automated security testing, reporting, CI/CD integration
- **Docker/containerization** - Isolated testing, networking, multi-container setups
- **Report generation** - JSON/HTML output, data visualization, compliance scoring

### Professional Competencies
- Breaking complex projects into incremental milestones (Level 1 → 2 → 3)
- Writing production-ready code with error handling and logging
- Creating professional documentation (README, code comments)
- Understanding enterprise security requirements
- Scalable architecture design (local → remote → multi-host)

---

## 🤝 Contributing

Contributions welcome! Here's how you can help:

### Ways to Contribute
- 🐛 Report bugs or security issues
- ✨ Suggest new security checks
- 📚 Improve documentation
- 🔧 Submit pull requests

### Contribution Process
1. Fork the repository
2. Create feature branch (`git checkout -b feature/NewCheck`)
3. Add your changes with tests
4. Commit (`git commit -m 'Add SSH cipher strength check'`)
5. Push (`git push origin feature/NewCheck`)
6. Open a Pull Request

### Development Setup
git clone https://github.com/yourusername/security-auditor.git
cd security-auditor
pip3 install -r requirements.txt

Make your changes
python3 auditor.py # Test locally


---

## 📚 References & Resources

### CIS Benchmarks
- [CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)

### Technologies Used
- [Paramiko Documentation](https://docs.paramiko.org/) - SSH implementation
- [Python-dotenv](https://pypi.org/project/python-dotenv/) - Environment management
- [Jinja2 Templates](https://jinja.palletsprojects.com/) - HTML generation

### Similar Tools (Inspiration)
- **Lynis** - Open-source security auditing tool for Linux
- **OpenSCAP** - SCAP compliance checking
- **Ansible Hardening** - Automated server hardening playbooks

---

## 📝 License

This project is licensed under the **MIT License**.

MIT License

Copyright (c) 2025 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

text

---

## 🙏 Acknowledgments

- **CIS Benchmarks** for establishing industry-standard security baselines
- **Paramiko maintainers** for robust SSH automation capabilities
- **Docker community** for containerization best practices
- **Open-source security community** for shared knowledge and tools

---

## ⚠️ Security & Legal Disclaimer

**IMPORTANT:** This tool is intended for **authorized security auditing only**.

### Legal Notice
- Only scan systems you **own** or have **explicit written permission** to audit
- Unauthorized scanning may violate computer fraud laws (CFAA in US, Computer Misuse Act in UK, etc.)
- The authors assume **no liability** for misuse of this software

### Security Best Practices
- **Never commit credentials** to version control (`.env` in `.gitignore`)
- **Use SSH keys** instead of passwords in production
- **Rotate credentials** regularly
- **Limit SSH access** with firewall rules and fail2ban
- **Review logs** for unauthorized access attempts

### Responsible Disclosure
If you discover security vulnerabilities in this tool:
1. **Do NOT** open a public GitHub issue
2. Email security concerns to: [divyanshsrivastava215@gmail.com]
3. Allow 90 days for patch before public disclosure

---

## 📧 Contact & Support

**Project Maintainer:** [Your Name]  
**GitHub:** [@yourusername](https://github.com/divyansh369)  
**Email:** your-email@example.com

### Getting Help
- 🐛 **Bug reports:** [Open an issue](https://github.com/divyansh369/security-auditor/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/divyansh369/security-auditor/discussions)
- 📧 **Direct contact:** For security issues or private inquiries

---

## 🌟 Project Stats

![GitHub stars](https://img.shields.io/github/stars/yourusername/security-auditor?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/security-auditor?style=social)
![GitHub issues](https://img.shields.io/github/issues/yourusername/security-auditor)
![GitHub license](https://img.shields.io/github/license/yourusername/security-auditor)

---

**Built with ❤️ for security automation, DevSecOps, and continuous compliance monitoring**

*"Security is not a product, but a process." - Bruce Schneier*

---

## 🎯 Quick Links

- [Installation](#-installation--setup)
- [Usage Examples](#-usage)
- [Adding Custom Checks](#adding-custom-security-checks)
- [Docker Testing](#-testing-with-docker)
- [Contributing](#-contributing)
- [Roadmap](#-development-roadmap)

---

**Last Updated:** November 15, 2025  
**Current Version:** 2.0 (Level 2 Complete)  

**Status:** ✅ Production-Ready for Single Remote Host Scanning

