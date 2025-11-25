import datetime
import os
import shutil

def rotate_reports():
    """
     :timestamp
     :
    """
    report_dir = "Reports"
    backup_dir = os.path.join(report_dir, "Backup")

    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(backup_dir, exist_ok=True)

    old_files = [file for file in os.listdir(report_dir) if file.endswith(".json") or file.endswith(".html")]

    if not old_files:
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_folder = os.path.join(backup_dir, f"backup_{timestamp}")
    os.makedirs(backup_folder, exist_ok=True)

    for file in old_files:
        src_path = os.path.join(report_dir, file)
        dst_path = os.path.join(backup_folder, file)
        shutil.move(src_path, dst_path)