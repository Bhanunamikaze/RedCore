#!/bin/bash

# Red-Core Enhanced Linux Privilege Escalation Framework
# Advanced privilege escalation reconnaissance with novel attack vectors  
# Built for authorized security testing and red team operations

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Global variables
VERBOSE=false
STEALTH=false
OUTPUT_FILE=""
QUICK_MODE=false

# Banner
banner() {
    echo -e "${RED}
██████╗ ███████╗██████╗       ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗     ██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║     ██║     ██║   ██║██████╔╝█████╗  
██╔══██╗██╔══╝  ██║  ██║     ██║     ██║   ██║██╔══██╗██╔══╝  
██║  ██║███████╗██████╔╝     ╚██████╗╚██████╔╝██║  ██║███████╗
╚═╝  ╚═╝╚══════╝╚═════╝       ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
                    ${WHITE}Enhanced Linux Privilege Escalation Framework v2.0${NC}"
    echo -e "${CYAN}[+] Red Team Linux Privilege Escalation Reconnaissance${NC}"
    echo -e "${YELLOW}[!] For Authorized Security Testing Only${NC}"
    echo ""
}

# Output function for logging
output() {
    echo -e "$1"
    if [ ! -z "$OUTPUT_FILE" ]; then
        echo -e "$1" | sed 's/\033\[[0-9;]*m//g' >> "$OUTPUT_FILE"
    fi
}

# Enhanced system reconnaissance
system_recon() {
    output "${GREEN}[*] ADVANCED SYSTEM RECONNAISSANCE${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    # Core system enumeration
    output "${YELLOW}[+] System Information & Kernel Analysis${NC}"
    uname -a 2>/dev/null
    output "Kernel: $(uname -r 2>/dev/null)"
    output "Architecture: $(uname -m 2>/dev/null)"
    output "Hostname: $(hostname 2>/dev/null)"
    output "Uptime: $(uptime 2>/dev/null)"
    
    # Enhanced kernel exploit detection
    output "\n${YELLOW}[+] Kernel Vulnerability Assessment${NC}"
    kernel_version=$(uname -r 2>/dev/null)
    output "Target Kernel: $kernel_version"
    
    # Comprehensive kernel CVE database
    case "$kernel_version" in
        3.*)
            output "${RED}[!] CRITICAL: Kernel 3.x - Multiple escalation vectors available${NC}"
            output "    - Dirty COW (CVE-2016-5195)"
            output "    - KASLR bypass techniques"
            output "    - Use-after-free vulnerabilities"
            ;;
        4.4.*)
            output "${RED}[!] HIGH: Kernel 4.4.x vulnerable to CVE-2017-16995${NC}"
            ;;
        4.8.*|4.9.*|4.10.*)
            output "${RED}[!] HIGH: af_packet overflow (CVE-2017-7308)${NC}"
            ;;
        4.15.*|4.19.*)
            output "${YELLOW}[!] MEDIUM: Check for CVE-2019-13272 (ptrace)${NC}"
            ;;
        5.*)
            output "${GREEN}[!] Recent kernel - Check for 0-day potential${NC}"
            ;;
    esac
    
    # Distribution and package manager analysis
    output "\n${YELLOW}[+] Distribution Intelligence & Package Vectors${NC}"
    if [ -f /etc/os-release ]; then
        source /etc/os-release 2>/dev/null
        output "Distribution: $NAME $VERSION"
        output "ID: $ID"
        output "Version ID: $VERSION_ID"
        
        # Package manager privilege escalation vectors
        output "${CYAN}[>] Package Manager Security Analysis:${NC}"
        
        # Check for writable package managers
        for pkg_mgr in apt apt-get yum dnf pacman zypper; do
            pkg_path=$(which $pkg_mgr 2>/dev/null)
            if [ ! -z "$pkg_path" ]; then
                output "Available: $pkg_path"
                if [ -w "$pkg_path" ]; then
                    output "${RED}[!] CRITICAL: $pkg_mgr is writable - RCE possible${NC}"
                fi
            fi
        done
        
        # Check package manager configurations
        if [ -r /etc/apt/sources.list ]; then
            output "${CYAN}[>] APT sources configuration accessible${NC}"
        fi
        
        # Look for package installation scripts
        find /var/lib/dpkg/info/ -name "*.postinst" -readable 2>/dev/null | head -5 | while read script; do
            output "${PURPLE}[>] Readable post-install script: $script${NC}"
        done
    fi
    
    # Cloud platform detection
    output "\n${YELLOW}[+] Cloud Platform & Metadata Analysis${NC}"
    
    # AWS detection
    if curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
        output "${RED}[!] AWS EC2 Instance Detected - IMDS accessible${NC}"
        output "${CYAN}[>] Attempting metadata extraction...${NC}"
        
        # Try to get IAM role
        iam_role=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
        if [ ! -z "$iam_role" ]; then
            output "${RED}[!] CRITICAL: IAM role accessible: $iam_role${NC}"
        fi
        
        # Get instance info
        instance_id=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
        output "Instance ID: $instance_id"
        
        # User data check
        user_data=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/user-data 2>/dev/null)
        if [ ! -z "$user_data" ] && [ "$user_data" != "404 - Not Found" ]; then
            output "${RED}[!] User data accessible - may contain credentials${NC}"
        fi
    fi
    
    # GCP detection  
    if curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ >/dev/null 2>&1; then
        output "${RED}[!] Google Cloud Platform Instance Detected${NC}"
        
        # Try to get service account
        service_account=$(curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/ 2>/dev/null)
        if [ ! -z "$service_account" ]; then
            output "${RED}[!] Service account accessible: $service_account${NC}"
        fi
    fi
    
    # Azure detection
    if curl -s --connect-timeout 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1; then
        output "${RED}[!] Microsoft Azure Instance Detected${NC}"
    fi
}

# Enhanced SUID/SGID analysis with GTFOBins integration
suid_analysis() {
    output "\n${GREEN}[*] ENHANCED SUID/SGID VULNERABILITY ANALYSIS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] SUID Binary Discovery & GTFOBins Cross-Reference${NC}"
    
    # Comprehensive SUID enumeration
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while IFS= read -r binary; do
        output "\n${CYAN}[>] Analyzing: $binary${NC}"
        ls -la "$binary" 2>/dev/null
        
        binary_name=$(basename "$binary")
        
        # Enhanced GTFOBins database with exploitation context
        case "$binary_name" in
            "vim"|"vi"|"nano"|"emacs")
                output "${RED}[!] CRITICAL: Text editor with SUID - Shell escape possible${NC}"
                output "    Exploit: Open file, :!/bin/sh or :shell"
                ;;
            "less"|"more"|"man"|"pager")
                output "${RED}[!] CRITICAL: Pager with SUID - Shell escape via !sh${NC}"
                output "    Exploit: !/bin/sh or !/bin/bash"
                ;;
            "find")
                output "${RED}[!] CRITICAL: find binary with SUID${NC}"
                output "    Exploit: find . -exec /bin/sh \\; -quit"
                ;;
            "awk"|"gawk")
                output "${RED}[!] CRITICAL: AWK with SUID${NC}"
                output "    Exploit: awk 'BEGIN {system(\"/bin/sh\")}'"
                ;;
            "python"|"python2"|"python3")
                output "${RED}[!] CRITICAL: Python interpreter with SUID${NC}"
                output "    Exploit: python -c 'import os; os.system(\"/bin/sh\")'"
                ;;
            "perl")
                output "${RED}[!] CRITICAL: Perl interpreter with SUID${NC}"
                output "    Exploit: perl -e 'exec \"/bin/sh\";'"
                ;;
            "ruby")
                output "${RED}[!] CRITICAL: Ruby interpreter with SUID${NC}"
                output "    Exploit: ruby -e 'exec \"/bin/sh\"'"
                ;;
            "nmap")
                output "${RED}[!] HIGH: Nmap with SUID - Interactive mode exploitation${NC}"
                output "    Exploit: nmap --interactive; !sh"
                ;;
            "tcpdump")
                output "${YELLOW}[!] MEDIUM: tcpdump with SUID - File read capability${NC}"
                ;;
            "cp"|"mv")
                output "${RED}[!] HIGH: File operation utility with SUID${NC}"
                output "    Exploit: Overwrite system files like /etc/passwd"
                ;;
            "tar"|"zip"|"unzip")
                output "${RED}[!] HIGH: Archive utility with SUID${NC}"
                output "    Exploit: Archive extraction to privileged locations"
                ;;
            "wget"|"curl")
                output "${YELLOW}[!] MEDIUM: Network utility with SUID${NC}"
                output "    Exploit: Download and execute malicious files"
                ;;
            "socat")
                output "${RED}[!] HIGH: socat with SUID - Network pivoting${NC}"
                ;;
        esac
        
        # Novel detection: Check for custom/unknown SUID binaries
        if [[ "$binary" == *"/tmp/"* ]] || [[ "$binary" == *"/var/tmp/"* ]] || [[ "$binary" == *"/dev/shm/"* ]]; then
            output "${RED}[!] CRITICAL ANOMALY: SUID binary in temporary location${NC}"
            output "    Likely planted backdoor or privilege escalation tool"
        fi
        
        # Check for non-standard ownership
        owner=$(stat -c "%U" "$binary" 2>/dev/null)
        if [ "$owner" != "root" ] && [ ! -z "$owner" ]; then
            output "${RED}[!] ANOMALY: Non-root SUID binary owner: $owner${NC}"
        fi
        
        # Check if binary is writable (major security flaw)
        if [ -w "$binary" ]; then
            output "${RED}[!] CRITICAL: SUID binary is writable - immediate escalation${NC}"
        fi
        
        # Check for SGID binaries with group write permissions
        if [ -g "$binary" ]; then
            group=$(stat -c "%G" "$binary" 2>/dev/null)
            output "${PURPLE}[!] SGID binary - Group: $group${NC}"
        fi
    done
    
    # Look for SUID shells (immediate escalation)
    output "\n${YELLOW}[+] Searching for SUID Shell Binaries${NC}"
    find / -type f -perm -4000 -name "*sh*" 2>/dev/null | while IFS= read -r shell; do
        output "${RED}[!] CRITICAL: SUID shell found: $shell${NC}"
        output "    Execute directly for root shell"
    done
}

# Enhanced process and service analysis
process_enumeration() {
    output "\n${GREEN}[*] PROCESS & SERVICE ATTACK SURFACE ANALYSIS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] Running Process Analysis & Exploitation Vectors${NC}"
    
    # Enhanced process enumeration with security context
    ps aux --no-headers 2>/dev/null | while IFS= read -r line; do
        user=$(echo $line | awk '{print $1}')
        pid=$(echo $line | awk '{print $2}')
        cpu=$(echo $line | awk '{print $3}')
        mem=$(echo $line | awk '{print $4}')
        cmd=$(echo $line | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
        
        # Focus on root processes that could be exploitable
        if [ "$user" = "root" ]; then
            case "$cmd" in
                *apache*|*httpd*|*nginx*|*lighttpd*)
                    output "${RED}[!] Web server as root: $cmd (PID: $pid)${NC}"
                    output "    Attack vectors: Config injection, log poisoning, module exploitation"
                    ;;
                *mysql*|*mariadb*|*postgres*|*mongodb*|*redis*)
                    output "${YELLOW}[!] Database server as root: $cmd (PID: $pid)${NC}"
                    output "    Attack vectors: SQL injection, weak auth, config files"
                    ;;
                *ssh*|*sshd*)
                    output "${CYAN}[>] SSH daemon as root: $cmd (PID: $pid)${NC}"
                    ;;
                *cron*|*systemd*)
                    output "${PURPLE}[>] System service: $cmd (PID: $pid)${NC}"
                    ;;
                *docker*|*containerd*)
                    output "${YELLOW}[!] Container runtime as root: $cmd (PID: $pid)${NC}"
                    output "    Attack vectors: Docker socket access, container escape"
                    ;;
                */tmp/*|*/var/tmp/*|*/dev/shm/*)
                    output "${RED}[!] SUSPICIOUS: Root process from temp dir: $cmd${NC}"
                    ;;
                *python*|*perl*|*ruby*|*bash*|*sh*)
                    if echo "$cmd" | grep -qE "\.(py|pl|rb|sh)"; then
                        output "${PURPLE}[!] Root script execution: $cmd (PID: $pid)${NC}"
                    fi
                    ;;
            esac
        fi
        
        # Check for processes running with capabilities
        if [ -r "/proc/$pid/status" ]; then
            caps=$(grep "CapEff" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
            if [ "$caps" != "0000000000000000" ] && [ ! -z "$caps" ]; then
                output "${CYAN}[>] Process with capabilities: $cmd (PID: $pid) - $caps${NC}"
            fi
        fi
    done
    
    # Service enumeration
    output "\n${YELLOW}[+] System Service Analysis${NC}"
    
    # systemd services
    if command -v systemctl >/dev/null 2>&1; then
        output "${CYAN}[>] Active systemd services:${NC}"
        systemctl list-units --type=service --state=active --no-pager 2>/dev/null | grep -E "(ssh|http|mysql|postgres|docker|ftp)" | head -10
        
        # Check for writable service files
        find /etc/systemd/system/ -name "*.service" -writable 2>/dev/null | while IFS= read -r service; do
            output "${RED}[!] CRITICAL: Writable systemd service: $service${NC}"
        done
    fi
    
    # Check for running containers
    if command -v docker >/dev/null 2>&1; then
        output "\n${YELLOW}[+] Container Analysis${NC}"
        docker ps 2>/dev/null && output "${YELLOW}[!] Docker containers detected${NC}"
        
        # Check for Docker socket access
        if [ -w /var/run/docker.sock ]; then
            output "${RED}[!] CRITICAL: Docker socket writable - container escape possible${NC}"
        fi
    fi
    
    # Process monitoring for cron detection
    if [ "$QUICK_MODE" = false ]; then
        output "\n${YELLOW}[+] Process Monitoring for Scheduled Tasks${NC}"
        output "${CYAN}[>] Monitoring process execution for 60 seconds...${NC}"
        
        ps_before=$(ps aux --no-headers 2>/dev/null)
        sleep 60
        ps_after=$(ps aux --no-headers 2>/dev/null)
        
        comm -13 <(echo "$ps_before" | sort) <(echo "$ps_after" | sort) | head -15 | while IFS= read -r new_proc; do
            output "${PURPLE}[>] New process detected: $new_proc${NC}"
        done
    fi
}

# Advanced sudo and privilege analysis  
sudo_analysis() {
    output "\n${GREEN}[*] SUDO RIGHTS & PRIVILEGE ANALYSIS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] Sudo Configuration Analysis${NC}"
    
    # Check sudo rights
    sudo_output=$(sudo -l 2>/dev/null)
    if [ $? -eq 0 ] && [ ! -z "$sudo_output" ]; then
        output "${CYAN}[>] Current user sudo rights:${NC}"
        echo "$sudo_output" | while IFS= read -r line; do
            output "    $line"
            
            # Analyze dangerous sudo permissions
            case "$line" in
                *"(ALL : ALL) ALL"*|*"(ALL) ALL"*)
                    output "${RED}[!] CRITICAL: Full sudo access detected${NC}"
                    ;;
                *"NOPASSWD"*)
                    output "${RED}[!] HIGH: Passwordless sudo detected${NC}"
                    cmd=$(echo "$line" | grep -oE "/[^,\s]+" | head -1)
                    if [ ! -z "$cmd" ]; then
                        output "    Command: $cmd"
                        
                        # Check GTFOBins for sudo escalation
                        case "$(basename $cmd)" in
                            "vim"|"nano"|"less"|"more")
                                output "${RED}[!] CRITICAL: Text editor/pager with sudo - shell escape${NC}"
                                ;;
                            "find"|"awk"|"python"|"perl"|"ruby")
                                output "${RED}[!] CRITICAL: Command injection possible${NC}"
                                ;;
                            "cp"|"mv"|"chmod"|"chown")
                                output "${RED}[!] HIGH: File manipulation with sudo${NC}"
                                ;;
                        esac
                    fi
                    ;;
            esac
        done
    else
        output "${YELLOW}[!] Unable to check sudo rights (no password or not allowed)${NC}"
    fi
    
    # Check sudoers file accessibility
    if [ -r /etc/sudoers ]; then
        output "${RED}[!] CRITICAL: /etc/sudoers file is readable${NC}"
        output "${CYAN}[>] Sudoers configuration:${NC}"
        grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^\s*$" | head -10
    fi
    
    # Check for sudoers.d directory
    if [ -d /etc/sudoers.d ]; then
        find /etc/sudoers.d/ -type f -readable 2>/dev/null | while IFS= read -r sudoer_file; do
            output "${YELLOW}[!] Readable sudoers.d file: $sudoer_file${NC}"
        done
    fi
    
    # Check for sudo version vulnerabilities
    sudo_version=$(sudo --version 2>/dev/null | head -1)
    if [ ! -z "$sudo_version" ]; then
        output "\n${YELLOW}[+] Sudo Version Analysis${NC}"
        output "Version: $sudo_version"
        
        # Check for known sudo CVEs
        case "$sudo_version" in
            *"1.8."*|*"1.9.0"*|*"1.9.1"*|*"1.9.2"*|*"1.9.3"*|*"1.9.4"*|*"1.9.5"*)
                output "${RED}[!] POTENTIAL: Check for CVE-2021-3156 (Baron Samedit)${NC}"
                ;;
        esac
    fi
}

# Enhanced network analysis
network_analysis() {
    output "\n${GREEN}[*] NETWORK ATTACK SURFACE & LATERAL MOVEMENT${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] Network Interface & Configuration Analysis${NC}"
    
    # Enhanced network interface enumeration
    if command -v ip >/dev/null 2>&1; then
        output "${CYAN}[>] Network interfaces (ip):${NC}"
        ip addr show 2>/dev/null | grep -E "(inet|ether)" | while IFS= read -r line; do
            output "    $line"
        done
        
        # Check routing table
        output "\n${CYAN}[>] Routing table:${NC}"
        ip route 2>/dev/null | head -5
    else
        output "${CYAN}[>] Network interfaces (ifconfig):${NC}"
        ifconfig 2>/dev/null | grep -E "(inet|ether)" | while IFS= read -r line; do
            output "    $line"
        done
    fi
    
    # Enhanced listening services analysis
    output "\n${YELLOW}[+] Listening Services & Attack Vectors${NC}"
    
    # Use ss if available, fallback to netstat
    if command -v ss >/dev/null 2>&1; then
        ss -tuln 2>/dev/null | grep LISTEN | while IFS= read -r line; do
            port=$(echo $line | awk '{print $5}' | sed 's/.*://')
            output "${CYAN}[>] Port $port listening${NC}"
            
            case "$port" in
                "22")
                    output "    ${GREEN}SSH - Credential brute force, key theft${NC}"
                    ;;
                "23")
                    output "    ${RED}Telnet - Cleartext credentials${NC}"
                    ;;
                "21")
                    output "    ${YELLOW}FTP - Anonymous access, credential theft${NC}"
                    ;;
                "80"|"8080"|"8000"|"8888")
                    output "    ${YELLOW}HTTP - Web application testing, SSRF${NC}"
                    ;;
                "443"|"8443")
                    output "    ${YELLOW}HTTPS - SSL/TLS analysis, web app testing${NC}"
                    ;;
                "3306")
                    output "    ${RED}MySQL - Database access, credential brute force${NC}"
                    ;;
                "5432")
                    output "    ${RED}PostgreSQL - Database exploitation${NC}"
                    ;;
                "6379")
                    output "    ${RED}Redis - Often no authentication required${NC}"
                    ;;
                "27017")
                    output "    ${RED}MongoDB - NoSQL injection, weak auth${NC}"
                    ;;
                "5984"|"5985")
                    output "    ${YELLOW}CouchDB - Database exploitation${NC}"
                    ;;
                "9200"|"9300")
                    output "    ${RED}Elasticsearch - Data exposure, RCE${NC}"
                    ;;
                "2375"|"2376")
                    output "    ${RED}Docker API - Container manipulation${NC}"
                    ;;
                "8086")
                    output "    ${YELLOW}InfluxDB - Time series database${NC}"
                    ;;
                "5000")
                    output "    ${PURPLE}Custom service - Manual investigation required${NC}"
                    ;;
                *)
                    if [ "$port" -gt 1024 ] && [ "$port" -lt 65536 ]; then
                        output "    ${PURPLE}High port - Likely custom service${NC}"
                    fi
                    ;;
            esac
        done
    else
        netstat -tuln 2>/dev/null | grep LISTEN | while IFS= read -r line; do
            port=$(echo $line | awk '{print $4}' | sed 's/.*://')
            output "${CYAN}[>] Port $port listening (netstat)${NC}"
        done
    fi
    
    # Network neighbors for lateral movement
    output "\n${YELLOW}[+] Network Neighbors & Lateral Movement Targets${NC}"
    
    # ARP table
    if command -v arp >/dev/null 2>&1; then
        arp_entries=$(arp -a 2>/dev/null | head -10)
        if [ ! -z "$arp_entries" ]; then
            output "${CYAN}[>] ARP table entries:${NC}"
            echo "$arp_entries" | while IFS= read -r entry; do
                output "    $entry"
            done
        fi
    fi
    
    # Network connections
    output "\n${CYAN}[>] Active network connections:${NC}"
    if command -v ss >/dev/null 2>&1; then
        ss -tuln 2>/dev/null | grep ESTAB | head -5
    else
        netstat -an 2>/dev/null | grep ESTABLISHED | head -5
    fi
    
    # Check for network configuration files
    output "\n${YELLOW}[+] Network Configuration Files${NC}"
    for config_file in /etc/hosts /etc/resolv.conf /etc/network/interfaces; do
        if [ -r "$config_file" ]; then
            output "${CYAN}[>] $config_file is readable${NC}"
        fi
    done
}

# Enhanced file system analysis
file_permissions() {
    output "\n${GREEN}[*] FILE SYSTEM PRIVILEGE ESCALATION VECTORS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] World-Writable Files & Directory Analysis${NC}"
    
    # Enhanced world-writable directory enumeration
    find / -type d -perm -o+w 2>/dev/null | head -30 | while IFS= read -r dir; do
        output "${CYAN}[>] World-writable directory: $dir${NC}"
        
        # Check if directory is in PATH
        if echo "$PATH" | grep -q "$dir"; then
            output "    ${RED}[!] CRITICAL: Directory in PATH - binary hijacking possible${NC}"
        fi
        
        # Check for scripts in writable directories
        find "$dir" -maxdepth 1 -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | head -3 | while IFS= read -r script; do
            output "    ${YELLOW}[!] Script in writable dir: $script${NC}"
        done
    done
    
    # World-writable files
    output "\n${YELLOW}[+] World-Writable Files${NC}"
    find / -type f -perm -o+w 2>/dev/null | head -20 | while IFS= read -r file; do
        output "${CYAN}[>] World-writable file: $file${NC}"
        
        # Check if it's a system binary
        if echo "$PATH" | xargs -d: -I {} find {} -name "$(basename $file)" 2>/dev/null | grep -q .; then
            output "    ${RED}[!] CRITICAL: System binary is writable${NC}"
        fi
    done
    
    # Enhanced sensitive files analysis
    output "\n${YELLOW}[+] Sensitive File Permission Analysis${NC}"
    
    sensitive_files=(
        "/etc/passwd:/etc/passwd"
        "/etc/shadow:/etc/shadow"  
        "/etc/sudoers:/etc/sudoers"
        "/etc/hosts:/etc/hosts"
        "/etc/ssh/sshd_config:/etc/ssh/sshd_config"
        "/etc/crontab:/etc/crontab"
        "/root/.ssh/id_rsa:/root/.ssh/id_rsa"
        "/home/*/.ssh/id_rsa:SSH private keys"
        "/var/log/auth.log:/var/log/auth.log"
        "/etc/mysql/my.cnf:MySQL config"
        "/etc/apache2/apache2.conf:Apache config"
        "/etc/nginx/nginx.conf:Nginx config"
    )
    
    for file_info in "${sensitive_files[@]}"; do
        file_pattern=$(echo "$file_info" | cut -d: -f1)
        description=$(echo "$file_info" | cut -d: -f2)
        
        find / -path "$file_pattern" -type f 2>/dev/null | while IFS= read -r file; do
            if [ -r "$file" ]; then
                perms=$(ls -la "$file" 2>/dev/null | awk '{print $1}')
                output "${CYAN}[>] $description: $file ($perms)${NC}"
                
                case "$file" in
                    *"shadow"*)
                        output "    ${RED}[!] CRITICAL: Shadow file readable - password hashes exposed${NC}"
                        ;;
                    *"id_rsa"*|*"id_ed25519"*|*"id_ecdsa"*)
                        output "    ${RED}[!] HIGH: SSH private key accessible${NC}"
                        ;;
                    *"sudoers"*)
                        output "    ${YELLOW}[!] Sudoers readable - check for misconfigurations${NC}"
                        ;;
                    *"passwd"*)
                        if [ -w "$file" ]; then
                            output "    ${RED}[!] CRITICAL: /etc/passwd is writable - can add root user${NC}"
                        fi
                        ;;
                esac
                
                # Check if file is writable
                if [ -w "$file" ]; then
                    output "    ${RED}[!] CRITICAL: File is writable${NC}"
                fi
            fi
        done
    done
    
    # Look for backup files with potential credentials
    output "\n${YELLOW}[+] Backup Files & Credential Hunting${NC}"
    
    backup_patterns=("*.bak" "*.backup" "*.old" "*.save" "*~")
    for pattern in "${backup_patterns[@]}"; do
        find /etc /home /var -name "$pattern" -readable 2>/dev/null | head -10 | while IFS= read -r backup; do
            output "${PURPLE}[>] Backup file found: $backup${NC}"
        done
    done
    
    # Check for interesting files in web directories
    web_dirs=("/var/www" "/usr/share/nginx" "/opt/www")
    for web_dir in "${web_dirs[@]}"; do
        if [ -d "$web_dir" ]; then
            find "$web_dir" -name "*.conf" -o -name "*.config" -o -name ".env" 2>/dev/null | head -5 | while IFS= read -r config; do
                output "${YELLOW}[!] Web config file: $config${NC}"
            done
        fi
    done
}

# Enhanced capabilities analysis
capability_analysis() {
    output "\n${GREEN}[*] LINUX CAPABILITIES SECURITY ANALYSIS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] Binary Capabilities Enumeration${NC}"
    
    if command -v getcap >/dev/null 2>&1; then
        getcap -r / 2>/dev/null | while IFS= read -r line; do
            binary=$(echo "$line" | awk '{print $1}')
            caps=$(echo "$line" | awk '{print $3}')
            
            output "${CYAN}[>] $binary${NC}"
            output "    Capabilities: $caps"
            
            # Analyze dangerous capabilities with exploitation methods
            case "$caps" in
                *"cap_dac_override"*)
                    output "    ${RED}[!] CRITICAL: CAP_DAC_OVERRIDE - can bypass file permissions${NC}"
                    output "    Exploit: Read/write any file on the system"
                    ;;
                *"cap_setuid"*)
                    output "    ${RED}[!] CRITICAL: CAP_SETUID - can change UID to root${NC}"
                    output "    Exploit: setuid(0) to become root"
                    ;;
                *"cap_setgid"*)
                    output "    ${RED}[!] HIGH: CAP_SETGID - can change GID${NC}"
                    ;;
                *"cap_sys_admin"*)
                    output "    ${RED}[!] CRITICAL: CAP_SYS_ADMIN - extensive system administration${NC}"
                    output "    Exploit: Mount filesystems, modify namespaces"
                    ;;
                *"cap_sys_ptrace"*)
                    output "    ${RED}[!] HIGH: CAP_SYS_PTRACE - can trace any process${NC}"
                    output "    Exploit: Inject code into root processes"
                    ;;
                *"cap_sys_module"*)
                    output "    ${RED}[!] CRITICAL: CAP_SYS_MODULE - can load kernel modules${NC}"
                    output "    Exploit: Load malicious kernel modules"
                    ;;
                *"cap_dac_read_search"*)
                    output "    ${YELLOW}[!] MEDIUM: CAP_DAC_READ_SEARCH - bypass read permissions${NC}"
                    ;;
                *"cap_fowner"*)
                    output "    ${YELLOW}[!] MEDIUM: CAP_FOWNER - bypass owner permission checks${NC}"
                    ;;
                *"cap_net_raw"*)
                    output "    ${YELLOW}[!] MEDIUM: CAP_NET_RAW - raw socket access${NC}"
                    ;;
            esac
        done
    else
        output "${YELLOW}[!] getcap not available - cannot enumerate capabilities${NC}"
    fi
    
    # Check process capabilities
    output "\n${YELLOW}[+] Process Capabilities Analysis${NC}"
    
    for pid in $(ps -eo pid --no-headers | head -20); do
        if [ -r "/proc/$pid/status" ]; then
            cap_eff=$(grep "CapEff" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
            if [ "$cap_eff" != "0000000000000000" ] && [ ! -z "$cap_eff" ]; then
                cmd=$(ps -p $pid -o comm= 2>/dev/null)
                output "${PURPLE}[>] Process $cmd (PID: $pid) has capabilities: $cap_eff${NC}"
            fi
        fi
    done
}

# Enhanced environment and credential analysis
environment_analysis() {
    output "\n${GREEN}[*] ENVIRONMENT & CREDENTIAL HARVESTING${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] Environment Variable Security Analysis${NC}"
    
    # Enhanced environment variable hunting
    env 2>/dev/null | while IFS= read -r var; do
        case "$var" in
            *PASSWORD*|*PASSWD*|*SECRET*|*TOKEN*|*KEY*|*API*|*AUTH*)
                output "${RED}[!] SENSITIVE: $var${NC}"
                ;;
            *URL*|*URI*|*HOST*|*SERVER*)
                output "${YELLOW}[!] CONNECTION: $var${NC}"
                ;;
            *PATH*)
                # Check for writable directories in PATH
                echo "$var" | cut -d= -f2 | tr ':' '\n' | while IFS= read -r path_dir; do
                    if [ -w "$path_dir" ] 2>/dev/null; then
                        output "${RED}[!] CRITICAL: Writable PATH directory: $path_dir${NC}"
                    fi
                done
                ;;
        esac
    done
    
    # Check for credentials in common environment files
    env_files=("~/.bashrc" "~/.bash_profile" "~/.zshrc" "~/.profile" "/etc/environment")
    for env_file in "${env_files[@]}"; do
        expanded_file=$(eval echo "$env_file")
        if [ -r "$expanded_file" ]; then
            grep -iE "(password|secret|token|key|api)" "$expanded_file" 2>/dev/null | while IFS= read -r cred; do
                output "${YELLOW}[!] Potential credential in $expanded_file: $cred${NC}"
            done
        fi
    done
    
    # Enhanced command history analysis
    output "\n${YELLOW}[+] Command History & Credential Mining${NC}"
    
    history_files=(
        "$HOME/.bash_history"
        "$HOME/.zsh_history" 
        "$HOME/.python_history"
        "$HOME/.mysql_history"
        "/root/.bash_history"
        "/home/*/.bash_history"
        "/home/*/.zsh_history"
    )
    
    for hist_pattern in "${history_files[@]}"; do
        find / -path "$hist_pattern" -type f 2>/dev/null | while IFS= read -r hist_file; do
            if [ -r "$hist_file" ]; then
                output "${CYAN}[>] Analyzing history: $hist_file${NC}"
                
                # Look for various credential patterns
                grep -iE "(password|passwd|secret|token|api|key)" "$hist_file" 2>/dev/null | head -3 | while IFS= read -r line; do
                    output "    ${YELLOW}[!] Credential pattern: $line${NC}"
                done
                
                # Look for database connections
                grep -iE "(mysql|psql|mongo|redis-cli)" "$hist_file" 2>/dev/null | head -3 | while IFS= read -r line; do
                    output "    ${PURPLE}[!] Database connection: $line${NC}"
                done
                
                # Look for SSH/SCP commands with potential keys
                grep -iE "(ssh|scp|rsync).*-i" "$hist_file" 2>/dev/null | head -3 | while IFS= read -r line; do
                    output "    ${CYAN}[!] SSH key usage: $line${NC}"
                done
                
                # Look for curl/wget with authentication
                grep -E "(curl|wget).*(-u|--user|Authorization)" "$hist_file" 2>/dev/null | head -3 | while IFS= read -r line; do
                    output "    ${YELLOW}[!] HTTP auth: $line${NC}"
                done
            fi
        done
    done
    
    # Check for SSH keys and configurations
    output "\n${YELLOW}[+] SSH Key & Configuration Analysis${NC}"
    
    # Find SSH private keys
    find /home /root -name "id_*" -type f 2>/dev/null | while IFS= read -r key; do
        if [ -r "$key" ]; then
            output "${RED}[!] SSH private key accessible: $key${NC}"
            
            # Check if key is password protected
            if head -5 "$key" | grep -q "ENCRYPTED"; then
                output "    ${YELLOW}[!] Key is encrypted${NC}"
            else
                output "    ${RED}[!] Key is NOT encrypted - immediate access${NC}"
            fi
        fi
    done
    
    # Check SSH configurations
    ssh_configs=("~/.ssh/config" "/etc/ssh/ssh_config")
    for ssh_config in "${ssh_configs[@]}"; do
        expanded_config=$(eval echo "$ssh_config")
        if [ -r "$expanded_config" ]; then
            output "${CYAN}[>] SSH config accessible: $expanded_config${NC}"
            
            # Look for potentially dangerous configurations
            grep -i "StrictHostKeyChecking" "$expanded_config" 2>/dev/null | while IFS= read -r line; do
                if echo "$line" | grep -qi "no"; then
                    output "    ${YELLOW}[!] StrictHostKeyChecking disabled${NC}"
                fi
            done
        fi
    done
}

# Enhanced cron and scheduled task analysis
cron_analysis() {
    output "\n${GREEN}[*] SCHEDULED TASK & AUTOMATION ANALYSIS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] Cron Job Vulnerability Assessment${NC}"
    
    # System cron jobs
    cron_files=("/etc/crontab" "/etc/cron.d/*" "/var/spool/cron/crontabs/*" "/var/spool/cron/*")
    
    for cron_pattern in "${cron_files[@]}"; do
        find / -path "$cron_pattern" -type f 2>/dev/null | while IFS= read -r cron_file; do
            if [ -r "$cron_file" ]; then
                output "${CYAN}[>] Cron file: $cron_file${NC}"
                
                # Check file permissions
                perms=$(ls -la "$cron_file" | awk '{print $1}')
                output "    Permissions: $perms"
                
                if [ -w "$cron_file" ]; then
                    output "    ${RED}[!] CRITICAL: Cron file is writable${NC}"
                fi
                
                # Analyze cron job content
                grep -v "^#" "$cron_file" 2>/dev/null | grep -v "^\s*$" | while IFS= read -r job; do
                    output "    Job: $job"
                    
                    # Check for relative paths (hijackable)
                    if echo "$job" | grep -qE "[^/]\w+"; then
                        cmd=$(echo "$job" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i}')
                        if ! echo "$cmd" | grep -q "^/"; then
                            output "    ${RED}[!] CRITICAL: Relative path in cron - $cmd${NC}"
                        fi
                    fi
                    
                    # Extract script paths and check if writable
                    echo "$job" | grep -oE '/[^[:space:]]+\.(sh|py|pl|rb)' | while IFS= read -r script; do
                        if [ -w "$script" ] 2>/dev/null; then
                            output "    ${RED}[!] CRITICAL: Writable cron script: $script${NC}"
                        elif [ ! -e "$script" ]; then
                            output "    ${YELLOW}[!] Missing cron script: $script (can be created)${NC}"
                        fi
                    done
                    
                    # Check for wildcard usage
                    if echo "$job" | grep -q "\*"; then
                        output "    ${YELLOW}[!] Wildcard usage detected - potential for exploitation${NC}"
                    fi
                done
            fi
        done
    done
    
    # User cron jobs
    output "\n${YELLOW}[+] User Cron Jobs${NC}"
    crontab -l 2>/dev/null | while IFS= read -r job; do
        output "${PURPLE}[>] User cron: $job${NC}"
    done
    
    # systemd timers
    output "\n${YELLOW}[+] Systemd Timer Analysis${NC}"
    
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-timers --no-pager 2>/dev/null | grep -v "^$" | head -10 | while IFS= read -r timer; do
            output "${CYAN}[>] Systemd timer: $timer${NC}"
        done
        
        # Check for writable timer files
        timer_dirs=("/etc/systemd/system" "/usr/lib/systemd/system" "~/.config/systemd/user")
        for timer_dir in "${timer_dirs[@]}"; do
            expanded_dir=$(eval echo "$timer_dir")
            if [ -d "$expanded_dir" ]; then
                find "$expanded_dir" -name "*.timer" -writable 2>/dev/null | while IFS= read -r timer_file; do
                    output "${RED}[!] CRITICAL: Writable systemd timer: $timer_file${NC}"
                done
            fi
        done
    fi
    
    # Check for at jobs
    if command -v at >/dev/null 2>&1; then
        output "\n${YELLOW}[+] AT Job Analysis${NC}"
        atq 2>/dev/null | while IFS= read -r at_job; do
            output "${PURPLE}[>] AT job: $at_job${NC}"
        done
    fi
}

# Container and virtualization analysis
container_analysis() {
    output "\n${GREEN}[*] CONTAINER & VIRTUALIZATION ANALYSIS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    # Check if we're in a container
    if [ -f /.dockerenv ]; then
        output "${RED}[!] Docker container environment detected${NC}"
        
        # Check for container escape vectors
        output "${YELLOW}[+] Container Escape Vector Analysis${NC}"
        
        # Check dangerous capabilities in container
        if command -v capsh >/dev/null 2>&1; then
            dangerous_caps=$(capsh --print 2>/dev/null | grep -E "(cap_sys_admin|cap_dac_override|cap_sys_ptrace|cap_sys_module)")
            if [ ! -z "$dangerous_caps" ]; then
                output "${RED}[!] CRITICAL: Container has dangerous capabilities${NC}"
                output "    $dangerous_caps"
                output "    Container escape likely possible"
            fi
        fi
        
        # Check for Docker socket access
        if [ -S /var/run/docker.sock ]; then
            output "${RED}[!] CRITICAL: Docker socket accessible from container${NC}"
            output "    Can control host Docker daemon - escape possible"
            
            if [ -w /var/run/docker.sock ]; then
                output "    ${RED}[!] Docker socket is writable - immediate escape${NC}"
            fi
        fi
        
        # Check for privileged container
        if grep -q "0" /proc/self/uid_map 2>/dev/null; then
            output "${RED}[!] Running in privileged container or with host UID mapping${NC}"
        fi
        
        # Check for host filesystem mounts
        mount 2>/dev/null | grep -E "(proc|sys|dev)" | while IFS= read -r host_mount; do
            if echo "$host_mount" | grep -qv "container"; then
                output "${YELLOW}[!] Host filesystem mount detected: $host_mount${NC}"
            fi
        done
        
        # Check for container metadata
        if [ -f /proc/1/cgroup ]; then
            cgroup_info=$(head -5 /proc/1/cgroup 2>/dev/null)
            output "${CYAN}[>] Container cgroup info:${NC}"
            echo "$cgroup_info" | while IFS= read -r line; do
                output "    $line"
            done
        fi
        
    elif [ -f /proc/vz/version ] 2>/dev/null; then
        output "${YELLOW}[!] OpenVZ container detected${NC}"
        
    elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
        output "${YELLOW}[!] LXC container detected${NC}"
        
    else
        # Check for other virtualization indicators
        dmesg 2>/dev/null | grep -iE "(vmware|virtualbox|qemu|kvm|xen)" | head -3 | while IFS= read -r virt_info; do
            output "${CYAN}[>] Virtualization detected: $virt_info${NC}"
        done
    fi
    
    # Check for Kubernetes environment
    if [ ! -z "$KUBERNETES_SERVICE_HOST" ]; then
        output "${YELLOW}[!] Kubernetes environment detected${NC}"
        output "Service Host: $KUBERNETES_SERVICE_HOST"
        
        # Check for service account token
        if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
            output "${RED}[!] Kubernetes service account token accessible${NC}"
            output "    Can potentially access Kubernetes API"
        fi
    fi
}

# Log file analysis for credentials and sensitive information
log_analysis() {
    output "\n${GREEN}[*] LOG FILE & SENSITIVE DATA ANALYSIS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] System Log Analysis${NC}"
    
    # Common log directories and files
    log_locations=(
        "/var/log/auth.log"
        "/var/log/secure" 
        "/var/log/messages"
        "/var/log/syslog"
        "/var/log/apache2/*.log"
        "/var/log/nginx/*.log"
        "/var/log/mysql/*.log"
        "/var/log/postgresql/*.log"
    )
    
    for log_pattern in "${log_locations[@]}"; do
        find / -path "$log_pattern" -type f -readable 2>/dev/null | head -5 | while IFS= read -r log_file; do
            output "${CYAN}[>] Accessible log: $log_file${NC}"
            
            # Check if log is writable (log injection possible)
            if [ -w "$log_file" ]; then
                output "    ${RED}[!] CRITICAL: Log file is writable - injection possible${NC}"
            fi
            
            # Look for credentials in logs (last 100 lines to avoid huge output)
            tail -100 "$log_file" 2>/dev/null | grep -iE "(password|secret|token|key)" | head -3 | while IFS= read -r cred_line; do
                output "    ${YELLOW}[!] Potential credential: $cred_line${NC}"
            done
            
            # Look for failed authentication attempts
            tail -100 "$log_file" 2>/dev/null | grep -iE "(failed|failure|authentication|login)" | head -2 | while IFS= read -r auth_line; do
                output "    ${PURPLE}[>] Auth event: $auth_line${NC}"
            done
        done
    done
    
    # Application-specific log analysis
    output "\n${YELLOW}[+] Application Log Analysis${NC}"
    
    # Web server logs
    web_log_dirs=("/var/log/apache2" "/var/log/nginx" "/var/log/httpd")
    for web_log_dir in "${web_log_dirs[@]}"; do
        if [ -d "$web_log_dir" ]; then
            find "$web_log_dir" -name "*.log" -readable 2>/dev/null | head -3 | while IFS= read -r web_log; do
                output "${CYAN}[>] Web server log: $web_log${NC}"
                
                # Look for potential vulnerabilities in access logs
                tail -50 "$web_log" 2>/dev/null | grep -E "(admin|login|password)" | head -2 | while IFS= read -r access; do
                    output "    ${YELLOW}[!] Interesting access: $access${NC}"
                done
            done
        fi
    done
    
    # Database logs
    db_log_dirs=("/var/log/mysql" "/var/log/postgresql" "/var/log/mongodb")
    for db_log_dir in "${db_log_dirs[@]}"; do
        if [ -d "$db_log_dir" ]; then
            find "$db_log_dir" -name "*.log" -readable 2>/dev/null | head -2 | while IFS= read -r db_log; do
                output "${CYAN}[>] Database log: $db_log${NC}"
            done
        fi
    done
}

# Configuration file analysis
config_analysis() {
    output "\n${GREEN}[*] CONFIGURATION FILE VULNERABILITY ANALYSIS${NC}"
    output "${BLUE}═══════════════════════════════════════════════════${NC}"
    
    output "${YELLOW}[+] Application Configuration Files${NC}"
    
    # Common config file patterns
    config_patterns=(
        "*.conf"
        "*.config" 
        "*.cfg"
        "*.ini"
        ".env"
        "*.properties"
        "*.json"
        "*.xml"
        "*.yml"
        "*.yaml"
    )
    
    # Search in common config directories
    config_dirs=("/etc" "/opt" "/usr/local/etc" "/var/www" "/home")
    
    for config_dir in "${config_dirs[@]}"; do
        if [ -d "$config_dir" ]; then
            for pattern in "${config_patterns[@]}"; do
                find "$config_dir" -name "$pattern" -readable 2>/dev/null | head -10 | while IFS= read -r config_file; do
                    # Skip large files to avoid performance issues
                    file_size=$(stat -c%s "$config_file" 2>/dev/null || echo 0)
                    if [ "$file_size" -lt 1048576 ]; then  # Less than 1MB
                        
                        # Look for credentials in config files
                        cred_found=$(grep -iE "(password|secret|token|key|api)" "$config_file" 2>/dev/null | head -3)
                        if [ ! -z "$cred_found" ]; then
                            output "${CYAN}[>] Config with credentials: $config_file${NC}"
                            echo "$cred_found" | while IFS= read -r cred; do
                                output "    ${YELLOW}[!] $cred${NC}"
                            done
                        fi
                        
                        # Look for database connection strings
                        db_conn=$(grep -iE "(host|server|database|db_|mysql|postgres|mongo)" "$config_file" 2>/dev/null | head -2)
                        if [ ! -z "$db_conn" ]; then
                            output "${PURPLE}[>] DB config: $config_file${NC}"
                        fi
                    fi
                done
            done
        fi
    done
    
    # Specific application configs
    output "\n${YELLOW}[+] Specific Application Configurations${NC}"
    
    # Apache/Nginx configs
    web_configs=("/etc/apache2/apache2.conf" "/etc/nginx/nginx.conf" "/etc/httpd/httpd.conf")
    for web_config in "${web_configs[@]}"; do
        if [ -r "$web_config" ]; then
            output "${CYAN}[>] Web server config readable: $web_config${NC}"
            
            # Look for document roots and includes
            grep -E "(DocumentRoot|root|include)" "$web_config" 2>/dev/null | head -3 | while IFS= read -r directive; do
                output "    $directive"
            done
        fi
    done
    
    # Database configs
    db_configs=("/etc/mysql/my.cnf" "/etc/postgresql/*/main/postgresql.conf")
    for db_config_pattern in "${db_configs[@]}"; do
        find / -path "$db_config_pattern" -readable 2>/dev/null | while IFS= read -r db_config; do
            output "${CYAN}[>] Database config readable: $db_config${NC}"
        done
    done
}

# Usage function
usage() {
    echo "Red-Core Enhanced Linux Privilege Escalation Framework"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -v, --verbose     Enable verbose output"
    echo "  -s, --stealth     Enable stealth mode (minimal writes to disk)"
    echo "  -q, --quick       Quick scan (skip time-intensive checks)"
    echo "  -o, --output FILE Output results to file"
    echo "  -h, --help        Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run with default settings"
    echo "  $0 -v -o results.txt  # Verbose output saved to file"
    echo "  $0 -s -q              # Quick stealth scan"
    echo ""
}

# Main execution function
main() {
    banner
    
    output "${GREEN}[*] Starting Red-Core Enhanced Enumeration...${NC}\n"
    
    # Execute all analysis modules
    system_recon
    suid_analysis
    sudo_analysis
    process_enumeration
    network_analysis
    file_permissions
    capability_analysis
    environment_analysis
    cron_analysis
    container_analysis
    log_analysis
    config_analysis
    
    output "\n${GREEN}[*] ENUMERATION COMPLETE${NC}"
    output "${WHITE}[*] ═══════════════════════════════════════════════════${NC}"
    output "${YELLOW}[!] Review highlighted items for privilege escalation opportunities${NC}"
    output "${RED}[!] Focus on CRITICAL and HIGH severity findings${NC}"
    output "${CYAN}[!] For authorized security testing only${NC}"
    
    if [ ! -z "$OUTPUT_FILE" ]; then
        output "\n${GREEN}[*] Results saved to: $OUTPUT_FILE${NC}"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -s|--stealth)
            STEALTH=true
            shift
            ;;
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Execute main function
main "$@"
