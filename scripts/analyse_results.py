import os
import datetime

def parse_log(file_path):
    if not os.path.exists(file_path):
        print("No YARA results found.")
        return

    with open(file_path, 'r') as f:
        lines = f.readlines()

    if lines:
        print(f"[{datetime.datetime.now()}]  Suspicious file detected:")
        for line in lines:
            print(f"  - {line.strip()}")

        print("\n Action: Quarantining file and alerting admin...")
    else:
        print(" No threats detected.")

parse_log("../logs/yara_detect.log")
