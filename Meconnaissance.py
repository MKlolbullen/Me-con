import os
import subprocess
import requests
import time
import argparse
from threading import Thread, Lock

class ScanResult:
    def __init__(self, url, vulnerable, issue, remediation):
        self.url = url
        self.vulnerable = vulnerable
        self.issue = issue
        self.remediation = remediation

def run_command(command, args, output_file, lock):
    cmd = [command] + args
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        if output_file:
            with lock:
                with open(output_file, 'a') as f:
                    f.write(output.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print(f"Error running {command}: {e.output.decode('utf-8')}")

def check_and_install_tool(tool_name):
    try:
        subprocess.check_call(['which', tool_name])
        print(f"{tool_name} is already installed.")
    except subprocess.CalledProcessError:
        print(f"{tool_name} is not installed. Installing...")
        try:
            subprocess.check_call(['pdtm', 'add', tool_name])
            print(f"{tool_name} installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error installing {tool_name}: {e.output.decode('utf-8')}")

def scan_url(url):
    print(f"Scanning: {url}")
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return ScanResult(url, True, "Potential vulnerability detected", "Review security")
        return ScanResult(url, False, "No issues detected", "")
    except requests.RequestException:
        return ScanResult(url, False, "Failed to reach", "Check URL or network")

def generate_report(results, output_file):
    with open(output_file, 'w') as f:
        for result in results:
            f.write(f"URL: {result.url}, Vulnerable: {result.vulnerable}, Issue: {result.issue}, Remediation: {result.remediation}\n")
    print(f"Scan report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Tool")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("--order", nargs='+', choices=['assetfinder', 'subfinder', 'dnsx', 'shuffledns', 'httpx', 'httprobe'], help="Order of tool execution")
    
    args = parser.parse_args()
    
    tools = [
        "assetfinder", "subfinder", "dnsx", "shuffledns", "httpx", "httprobe",
        "alterx", "gau", "naabu", "altdns", "goaltdns", "gotator",
        "ripgen", "dnsgen", "dmut", "permdns", "str-replace", "dnscewl", "regulator"
    ]

    for tool in tools:
        check_and_install_tool(tool)

    subprocess.check_call(['python3', '-m', 'pip', 'uninstall', 'autorecon', '-y'])
    subprocess.check_call(['python3', '-m', 'pip', 'install', 'git+https://github.com/Tib3rius/AutoRecon.git'])

    osint_dir = os.path.expanduser("~/work/osint")
    if not os.path.exists(osint_dir):
        os.makedirs(osint_dir, 0o755)

    domain = args.domain.strip()
    domain_dir = os.path.expanduser(f"~/work/{domain}")
    if not os.path.exists(domain_dir):
        os.makedirs(domain_dir, 0o755)

    lock = Lock()
    
    if args.order:
        order = args.order
    else:
        order = ["assetfinder", "subfinder", "dnsx", "shuffledns", "httpx", "httprobe"]

    threads = []

    for tool in order:
        if tool == "assetfinder":
            print("Running Assetfinder...")
            assetfinder_file = os.path.join(domain_dir, "dom_assetfinder.txt")
            t = Thread(target=run_command, args=("assetfinder", [domain], assetfinder_file, lock))
            t.start()
            threads.append(t)
        elif tool == "subfinder":
            print("Running Subfinder...")
            subfinder_file = os.path.join(domain_dir, "dom_subfinder.txt")
            t = Thread(target=run_command, args=("subfinder", ["-d", domain], subfinder_file, lock))
            t.start()
            threads.append(t)
        elif tool == "dnsx":
            print("Running Subfinder with dnsx...")
            dnsx_file = os.path.join(domain_dir, "doms_dnsx.txt")
            t = Thread(target=run_command, args=("subfinder", ["-silent", "-d", domain], "", lock))
            t.start()
            threads.append(t)
            t = Thread(target=run_command, args=("dnsx", ["-silent", "-a", "-resp"], dnsx_file, lock))
            t.start()
            threads.append(t)
        elif tool == "shuffledns":
            print("Combining results...")
            summary_file = os.path.join(domain_dir, "dom_summary.txt")
            run_command("sort", ["-u", assetfinder_file, subfinder_file, dnsx_file], summary_file, lock)
            print("Running Shuffledns...")
            shuffledns_file = os.path.join(domain_dir, "doms_resolved.txt")
            t = Thread(target=run_command, args=("shuffledns", ["-d", domain, "-list", summary_file, "-r", "/usr/share/sniper/plugins/Sublist3r/subbrute/resolvers.txt", "-mode", "resolve"], shuffledns_file, lock))
            t.start()
            threads.append(t)
        elif tool == "httpx":
            print("Running httpx...")
            httpx_file = os.path.join(domain_dir, "doms_tech_codes.txt")
            t = Thread(target=run_command, args=("httpx", ["-title", "-tech-detect", "-status-code", "-l", shuffledns_file], httpx_file, lock))
            t.start()
            threads.append(t)
        elif tool == "httprobe":
            print("Running httprobe...")
            httprobe_file = os.path.join(domain_dir, "doms_http.txt")
            t = Thread(target=run_command, args=("httprobe", ["-l", shuffledns_file], httprobe_file, lock))
            t.start()
            threads.append(t)

    for t in threads:
        t.join()

    other_tools = [
        {"name": "alterx", "args": ["-l", shuffledns_file], "output": os.path.join(domain_dir, "alterx.txt")},
        {"name": "gau", "args": ["-o", os.path.join(domain_dir, "gau.txt"), domain], "output": ""},
        {"name": "naabu", "args": ["-iL", shuffledns_file], "output": os.path.join(domain_dir, "naabu.txt")},
        {"name": "altdns", "args": ["-i", shuffledns_file], "output": os.path.join(domain_dir, "altdns.txt")},
        {"name": "goaltdns", "args": ["-w", shuffledns_file], "output": os.path.join(domain_dir, "goaltdns.txt")},
        {"name": "gotator", "args": ["-d", shuffledns_file], "output": os.path.join(domain_dir, "gotator.txt")},
        {"name": "ripgen", "args": ["-i", shuffledns_file], "output": os.path.join(domain_dir, "ripgen.txt")},
        {"name": "dnsgen", "args": ["-l", shuffledns_file], "output": os.path.join(domain_dir, "dnsgen.txt")},
        {"name": "dmut", "args": ["-d", shuffledns_file], "output": os.path.join(domain_dir, "dmut.txt")},
        {"name": "permdns", "args": ["-d", shuffledns_file], "output": os.path.join(domain_dir, "permdns.txt")},
        {"name": "str-replace", "args": ["-l", shuffledns_file], "output": os.path.join(domain_dir, "str-replace.txt")},
{"name": "dnscewl", "args": ["-d", shuffledns_file], "output": os.path.join(domain_dir, "dnscewl.txt")},
        {"name": "regulator", "args": ["-d", shuffledns_file], "output": os.path.join(domain_dir, "regulator.txt")},
    ]

    threads = []
    for tool in other_tools:
        t = Thread(target=run_command, args=(tool["name"], tool["args"], tool["output"], lock))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    with open(shuffledns_file, 'r') as f:
        urls = [line.strip() for line in f]

    results = [scan_url(url) for url in urls]
    report_file = os.path.join(domain_dir, "scan_report.txt")
    generate_report(results, report_file)

    print(f"Subdomain enumeration completed and results are saved in {domain_dir}")

if __name__ == "__main__":
    main()