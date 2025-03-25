from utils.registry_checker import check_registry_keys
from utils.process_monitor import check_suspicious_processes
from utils.file_checker import scan_with_yara

def run_detection():
    result = ""

    reg_keys = check_registry_keys([
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    ])
    result += f"레지스트리 탐지: {reg_keys}\n"

    procs = check_suspicious_processes()
    result += f"프로세스 탐지: {procs}\n"

    yara_match = scan_with_yara("C:\\Users\\user\\Downloads\\suspicious.exe")
    result += f"YARA 탐지: {yara_match}\n"

    return result
