from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
from common import Utils

report_folder = "Reports"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s"
)
logger = logging.getLogger(__name__)

def scan_single_machine(machine) -> dict:
    result = []
    pass_cnt = fail_cnt = 0
    compliance_score = 0

    hostname = machine.get('Hostname')
    username = machine.get('username')
    password = machine.get('password')
    
    client = None
    util = Utils(hostname,username,password)
    
    try:
        client = util.create_ssh_connection()
        if client:
            result = util.run_security_checks(client,report_folder)
            for r in result:
                status = "✅ PASS" if r["status"]=="PASS" else "❌ FAIL"
                logger.info(f"[{hostname}] {r['name']:<30} {status}")

            pass_cnt = sum(1 for r in result if r["status"] == "PASS")
            fail_cnt = sum(1 for r in result if r["status"] == "FAIL")
            total_checks = len(result)
            compliance_score = (pass_cnt / total_checks) * 100 if total_checks > 0 else 0
        
            return {
                "hostname": hostname,
                "pass_cnt": pass_cnt,
                "fail_cnt": fail_cnt,
                "score": compliance_score,
                "results": result
            }
        return {
            "hostname": hostname,
            "pass_cnt": pass_cnt,
            "fail_cnt": fail_cnt,
            "score": compliance_score,
            "results": result
        }
    finally:
        if client:
            client.close()
            logger.info(f"\n[{hostname}] ✅ SSH connection closed.")
            
if __name__=="__main__":
    Utils.rotate_reports()
    results = []
    try:
        with open('hosts.json','r') as f:
            machines = json.load(f)

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(scan_single_machine, machine) for machine in machines]
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logging.error(f"Error scanning machine: {e}")
    except Exception as e:
        logger.error(f"Failed to load machines.json: {e}")
        machines = []
