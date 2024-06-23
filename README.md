## Bug Bounty Tool

This tool is designed to automate various tasks in the bug bounty process, including subdomain enumeration, DNS querying, and website analysis. It leverages multiple tools to provide comprehensive results and generates detailed reports.

Big shout out to https://github.com/Tib3rius/AutoRecon
for inspiration, and implementation of his code into the project. 

### Features

- **Assetfinder**: Finds related domains and subdomains.
- **Subfinder**: Performs passive subdomain enumeration.
- **DNSx**: Fast DNS toolkit.
- **Shuffledns**: Wrapper for DNS resolvers.
- **HTTPx**: Probes HTTP servers.
- **Httprobe**: Probes working HTTP/HTTPS servers.
- **Alterx**: Subdomain alteration tool.
- **GAU**: Fetches URLs from web archives.
- **Naabu**: Fast port scanner.
- **Altdns**: Generates subdomain permutations.
- **Goaltdns**: Generates pattern-based subdomains.
- **Gotator**: Subdomain permutation tool.
- **Ripgen**: DNS permutation generator.
- **DNSgen**: Generates realistic domain names.
- **DMUT**: Domain mutation tool.
- **PermDNS**: DNS permutation tool.
- **Str-replace**: String replacement tool for lists.
- **DNScewl**: Generates DNS wordlists.
- **Regulator**: Domain and subdomain enumeration regulator.

### Prerequisites

Ensure `go` and `pipx` are installed on your system:
```bash
sudo apt install golang
python3 -m pip install pipx
pipx ensurepath
```

### Installation

Clone the repository and navigate into the directory:
```bash
git clone https://github.com/yourusername/bug_bounty_tool.git
cd bug_bounty_tool
```

### Usage

Run the script with the desired arguments:
```bash
python3 bug_bounty_tool.py example.com --threads 10 --order assetfinder subfinder dnsx shuffledns httpx httprobe
```

### Command-Line Arguments

- `domain`: Domain to scan (required).
- `--threads`: Number of threads to use (default: 5).
- `--order`: Order of tool execution (default: assetfinder subfinder dnsx shuffledns httpx httprobe).
- `-h`, `--help`: Show help message and exit.
- `-?`: Show help message and exit.

### Example

To scan `example.com` with 10 threads and a specific order of tools:
```bash
python3 bug_bounty_tool.py example.com --threads 10 --order assetfinder subfinder dnsx shuffledns httpx httprobe
```

### License

This project is licensed under the MIT License - see the LICENSE file for details.

### Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

### Contact

For any issues or questions, please contact [].

---

Feel free to modify the content according to your project details and preferences.
