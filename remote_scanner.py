import logging
import os
import json
import datetime
import pathlib
import socket
import paramiko
import dotenv
import shlex
from templates.report_template import generate_html_report
# from Utils import rotate_reports
from common import Utils

report_folder = "Reports"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s"
)
logger = logging.getLogger(__name__)

def scan_single_machine(machine) -> dict:
    hostname = machine.get('Hostname')
    username = machine.get('username')
    password = machine.get('password')

    util = Utils(hostname,username,password)
    client = util.create_ssh_connection()

    if client:
        result = util.run_security_checks(client,report_folder)
        for r in result:
            status = "✅ PASS" if r["status"]=="PASS" else "❌ FAIL"
            logger.info(f"{r['name']:<30} {status} (Actual: {r['actual_value']}, Expected: {r['expected']})")

        pass_cnt = sum(1 for r in result if r["status"] == "PASS")
        fail_cnt = sum(1 for r in result if r["status"] == "FAIL")
        total_checks = len(result)
        compliance_score = (pass_cnt / total_checks) * 100 if total_checks > 0 else 0
    
        transport = client.get_transport()

    if transport and transport.is_active():
        client.close()
        logger.info("\n✅ SSH connection closed.")

    return {
        "hostname": hostname,
        "pass_count": pass_cnt,
        "fail_count": fail_cnt,
        "total_checks": total_checks,
        "compliance_score": compliance_score
    }

if __name__=="__main__":
    
    Utils.rotate_reports()
    
    try:
        results = []
        with open('hosts.json','r') as f:
            machines = json.load(f)
            for machine in machines:
                results.append(scan_single_machine(machine))

    except Exception as e:
        logger.error(f"Failed to load machines.json: {e}")
        machines = []