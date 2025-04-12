
# Incident Response Project: YARA Rules, Ansible, Python, and Linux

This project demonstrates an automated **incident response** process for detecting and quarantining malicious files using **YARA rules**, **Ansible**, **Python**, and a **Linux host**. It includes the detection of suspicious attack tools (e.g., Mimikatz, PowerSploit, LinPEAS) and the automated movement of detected files to a quarantine folder.

## Project Overview

This project automates the following steps:
1. **YARA Rule Detection**: Detect known attacker tools (Windows and Linux) using YARA rules.
2. **Ansible Playbook Execution**: Use Ansible to orchestrate the scanning, file quarantine, and logging of suspicious files.
3. **Dynamic Quarantine**: Automatically quarantine detected files based on YARA output.

---

## Requirements

- **YARA**: A tool to create rules for identifying malicious files and patterns.
- **Ansible**: For automation and orchestration of the quarantine process.
- **Python**: For any auxiliary scripting and handling complex file parsing.
- **Linux (Ubuntu/Debian)**: For running the YARA scans, Ansible playbooks, and managing quarantined files.
- **Network Connectivity**: Between your host machine and the target machine (if remote detection).

---

## Setup

### 1. Install YARA

To use the YARA rules, you need to install YARA on your Linux machine.

There are a task in the ansible playbook which will install yara for you, but if you want to do it manually, you can follow these steps
```bash
sudo apt update
sudo apt install yara
```

Alternatively, if you want to install YARA from source, follow the instructions from the official [YARA GitHub repository](https://github.com/VirusTotal/yara).

### 2. Install Ansible

To install Ansible, run the following commands:

```bash
sudo apt update
sudo apt install ansible
```

### 3. Clone the Repository

Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/incident-response-yara.git
cd incident-response-yara
```

---

## Configuration

### YARA Rules

The **YARA rules** are stored in the `rules/` directory. The `suspicious.yar` file contains patterns to detect known attack tools. You can modify or add more rules as needed.

### Ansible Playbooks

- **Playbook**: The `playbook.yml` file contains the main logic for:
  - Running the YARA scan
  - Processing the results
  - Moving suspicious files to the quarantine directory

### Python Scripts

Additional Python scripts can be added to further process or log incidents, though this project currently focuses on Ansible and YARA.

---

## Usage

### 1. Run the YARA Scan

To manually run the YARA scan (you can modify the path to scan a specific directory):

```bash
yara -r rules/suspicious.yar /path/to/scan
```

This will run the YARA rules against the specified directory or file and output the results.

### 2. Run the Ansible Playbook

The Ansible playbook will execute the entire incident response process:

```bash
ansible-playbook playbook.yml -i inventory
```

- **Inventory File**: The `inventory` file contains the target machine(s) you want to run the playbook on. Update it with the appropriate host information (or use `localhost` for a local scan).
- The playbook will:
  - install yara
  - copy the YARA rules to the target
  - Run YARA scans
  - Capture YARA output
  - Quarantine any detected files

---

## Example Output

When YARA detects a suspicious file, you will see output similar to this:

```bash
Suspicious_Known_Attack_Tools /tmp/LinPEAS.sh
Suspicious_Known_Attack_Tools /tmp/chisel
```

Files like `/tmp/LinPEAS.sh` or `/tmp/chisel` will be quarantined by the playbook, and the quarantine will be located in `/tmp/quarantine/`.

---

## Quarantine Process

The Ansible playbook will:
1. Create a quarantine directory (`/tmp/quarantine`).
2. Move any detected malicious files to this quarantine directory.
3. Log the quarantined files and any other relevant information for further analysis.

---
## Python script

The python script inside the scrips folder can be interesting to customize

```bash
python3 scripts/analyse_results.py
```


## Customization

You can customize this project by:
1. **Adding More YARA Rules**: Modify or add more rules in the `rules/` folder for specific tools or threats you want to detect.
2. **Changing Quarantine Locations**: Modify the Ansible playbook to quarantine files in a different directory if needed.
3. **Integrating Other Security Tools**: You can integrate other tools like **OSSEC**, **Wazuh**, or **Snort** for a more comprehensive incident response system.

---

## License

This project is licensed under the GPL-3 License - see the [LICENSE](LICENSE) file for details.

---

## Conclusion

This project provides a simple but effective way to automate the detection and quarantine of malicious files based on YARA rules, using Ansible for automation and Python for any additional scripting. It can be easily expanded and customized to meet your specific incident response needs.

---
