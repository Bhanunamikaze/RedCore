#!/bin/bash

# Red-Core Advanced Linux Enumeration Script
# Enhanced privilege escalation reconnaissance with novel attack vectors
# For authorized security testing only

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${RED}
██████╗ ███████╗██████╗       ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗     ██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║     ██║     ██║   ██║██████╔╝█████╗  
██╔══██╗██╔══╝  ██║  ██║     ██║     ██║   ██║██╔══██╗██╔══╝  
██║  ██║███████╗██████╔╝     ╚██████╗╚██████╔╝██║  ██║███████╗
╚═╝  ╚═╝╚══════╝╚═════╝       ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
${NC}"

echo -e "${CYAN}[+] Advanced Linux Privilege Escalation Enumeration${NC}"
echo -e "${YELLOW}[!] For Authorized Security Testing Only${NC}"
echo ""

# Core enumeration functions

system_recon() {
    echo -e "${GREEN}[*] SYSTEM RECONNAISSANCE${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    # Basic system info with attack context
    echo -e "${YELLOW}[+] System Information & Attack Surface${NC}"
    uname -a
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    
    # Kernel exploit detection
    echo -e "\n${YELLOW}[+] Kernel Exploit Vectors${NC}"
    kernel_version=$(uname -r)
    echo "Kernel Version: $kernel_version"
    
    # Check for known vulnerable kernels
    if [[ "$kernel_version" =~ ^3\. ]] || [[ "$kernel_version" =~ ^4\.4\. ]]; then
        echo -e "${RED}[!] POTENTIAL: Dirty COW (CVE-2016-5195) candidate${NC}"
    fi
    
    if [[ "$kernel_version" =~ ^4\.8\. ]] || [[ "$kernel_version" =~ ^4\.10\. ]]; then
        echo -e "${RED}[!] POTENTIAL: af_packet overflow (CVE-2017-7308) candidate${NC}"
    fi
    
    # Distribution enumeration
    echo -e "\n${YELLOW}[+] Distribution & Package Manager Attack Vectors${NC}"
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        echo "Distribution: $NAME $VERSION"
        
        # Package manager privilege escalation vectors
        echo -e "${CYAN}[>] Package Manager Enumeration:${NC}"
        which apt apt-get yum dnf pacman zypper 2>/dev/null | while read pkg_mgr; do
            echo "Available: $pkg_mgr"
            # Check for package manager privilege escalation
            if [ -w "$pkg_mgr" ]; then
                echo -e "${RED}[!] CRITICAL: $pkg_mgr is writable - potential privilege escalation${NC}"
            fi
        done
    fi
}

suid_analysis() {
    echo -e "\n${GREEN}[*] SUID/SGID BINARY ANALYSIS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    echo -e "${YELLOW}[+] SUID Binary Discovery & Exploitation Vectors${NC}"
    
    # Enhanced SUID enumeration with GTFOBins integration
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read binary; do
        echo -e "\n${CYAN}[>] Analyzing: $binary${NC}"
        ls -la "$binary"
        
        # Extract binary name for GTFOBins analysis
        binary_name=$(basename "$binary")
        
        # Known GTFOBins SUID exploitable binaries
        case "$binary_name" in
            "vim"|"nano"|"less"|"more"|"find"|"awk"|"python"|"python3"|"perl"|"ruby")
                echo -e "${RED}[!] HIGH PRIORITY: $binary_name has known SUID exploitation methods${NC}"
                ;;
            "nmap"|"tcpdump"|"wireshark")
                echo -e "${RED}[!] HIGH PRIORITY: $binary_name can be used for privilege escalation${NC}"
                ;;
            "exim"|"sendmail")
                echo -e "${YELLOW}[!] MEDIUM: Mail server binary - check for CVEs and injection vectors${NC}"
                ;;
        esac
        
        # Novel attack vectors - check for custom binaries in unusual locations
        if [[ "$binary" == *"/tmp/"* ]] || [[ "$binary" == *"/var/tmp/"* ]]; then
            echo -e "${RED}[!] CRITICAL ANOMALY: SUID binary in temporary directory - likely backdoor${NC}"
        fi
        
        # Check for binaries with unusual ownership patterns
        owner=$(stat -c "%U" "$binary" 2>/dev/null)
        if [ "$owner" != "root" ]; then
            echo -e "${RED}[!] ANOMALY: Non-root owned SUID binary - potential privilege escalation${NC}"
        fi
    done
}

process_enumeration() {
    echo -e "\n${GREEN}[*] PROCESS & SERVICE ANALYSIS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    echo -e "${YELLOW}[+] Running Processes - Privilege Escalation Candidates${NC}"
    
    # Process enumeration with exploitation context
    ps aux --no-headers | while read line; do
        user=$(echo $line | awk '{print $1}')
        pid=$(echo $line | awk '{print $2}')
        cmd=$(echo $line | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
        
        # Highlight processes running as root that might be exploitable
        if [ "$user" = "root" ]; then
            # Check for web servers running as root (potential for exploitation)
            if echo "$cmd" | grep -qE "(apache|httpd|nginx|lighttpd|tomcat)"; then
                echo -e "${RED}[!] Web server running as root: $cmd (PID: $pid)${NC}"
            fi
            
            # Check for database servers
            if echo "$cmd" | grep -qE "(mysql|postgres|mongodb|redis)"; then
                echo -e "${YELLOW}[!] Database server as root: $cmd (PID: $pid)${NC}"
            fi
            
            # Check for custom applications
            if echo "$cmd" | grep -qE "^\./" && ! echo "$cmd" | grep -qE "(systemd|kernel|kthread)"; then
                echo -e "${PURPLE}[!] Custom root process: $cmd (PID: $pid)${NC}"
            fi
        fi
    done
    
    # Process monitoring for privilege escalation
    echo -e "\n${YELLOW}[+] Process Monitoring - Detecting Privilege Changes${NC}"
    echo -e "${CYAN}[>] Monitoring process execution for 30 seconds...${NC}"
    
    # Novel technique: Process execution monitoring
    ps_before=$(ps aux --no-headers)
    sleep 30
    ps_after=$(ps aux --no-headers)
    
    echo -e "${CYAN}[>] New processes detected:${NC}"
    comm -13 <(echo "$ps_before" | sort) <(echo "$ps_after" | sort) | head -10
}

network_analysis() {
    echo -e "\n${GREEN}[*] NETWORK ATTACK SURFACE${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    echo -e "${YELLOW}[+] Network Configuration & Lateral Movement Vectors${NC}"
    
    # Network interface enumeration
    echo -e "${CYAN}[>] Network Interfaces:${NC}"
    ip addr show 2>/dev/null || ifconfig 2>/dev/null
    
    # Listening services analysis
    echo -e "\n${YELLOW}[+] Listening Services - Attack Vectors${NC}"
    netstat -tuln 2>/dev/null | grep LISTEN | while read line; do
        port=$(echo $line | awk '{print $4}' | sed 's/.*://')
        echo -e "${CYAN}[>] Port $port listening${NC}"
        
        # Classify service types and attack vectors
        case "$port" in
            "22") echo -e "    ${GREEN}SSH - Check for weak credentials/keys${NC}" ;;
            "80"|"8080"|"8000") echo -e "    ${YELLOW}HTTP - Web application testing target${NC}" ;;
            "443"|"8443") echo -e "    ${YELLOW}HTTPS - SSL/TLS analysis, web application testing${NC}" ;;
            "3306") echo -e "    ${RED}MySQL - Database access, credential testing${NC}" ;;
            "5432") echo -e "    ${RED}PostgreSQL - Database access${NC}" ;;
            "6379") echo -e "    ${RED}Redis - Often misconfigured, no auth${NC}" ;;
            "27017") echo -e "    ${RED}MongoDB - NoSQL injection, misconfig${NC}" ;;
            *) echo -e "    ${PURPLE}Custom service - Manual investigation required${NC}" ;;
        esac
    done
    
    # ARP table analysis for lateral movement
    echo -e "\n${YELLOW}[+] ARP Table - Lateral Movement Targets${NC}"
    arp -a 2>/dev/null | head -20
}

file_permissions() {
    echo -e "\n${GREEN}[*] FILE SYSTEM PRIVILEGE ESCALATION${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    echo -e "${YELLOW}[+] World-Writable Files & Directories${NC}"
    
    # World-writable directories (potential for exploitation)
    find / -type d -perm -o+w 2>/dev/null | head -20 | while read dir; do
        echo -e "${CYAN}[>] World-writable directory: $dir${NC}"
        
        # Check if it's in PATH - potential for hijacking
        if echo "$PATH" | grep -q "$dir"; then
            echo -e "    ${RED}[!] CRITICAL: Directory is in PATH - binary hijacking possible${NC}"
        fi
    done
    
    # Configuration files with weak permissions
    echo -e "\n${YELLOW}[+] Sensitive Files - Weak Permissions${NC}"
    sensitive_files=(
        "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/hosts"
        "/etc/ssh/sshd_config" "/etc/crontab" "/root/.ssh/id_rsa"
        "/home/*/.ssh/id_rsa" "/var/log/auth.log"
    )
    
    for file_pattern in "${sensitive_files[@]}"; do
        find / -path "$file_pattern" -type f 2>/dev/null | while read file; do
            perms=$(ls -la "$file" 2>/dev/null | awk '{print $1}')
            if [ ! -z "$perms" ]; then
                echo -e "${CYAN}[>] $file: $perms${NC}"
                
                # Check for readable sensitive files
                if [ -r "$file" ]; then
                    case "$file" in
                        *"shadow"*) echo -e "    ${RED}[!] CRITICAL: Shadow file readable${NC}" ;;
                        *"id_rsa"*) echo -e "    ${RED}[!] HIGH: SSH private key accessible${NC}" ;;
                        *"sudoers"*) echo -e "    ${YELLOW}[!] Sudoers file readable - check for misconfigurations${NC}" ;;
                    esac
                fi
            fi
        done
    done
}

capability_analysis() {
    echo -e "\n${GREEN}[*] LINUX CAPABILITIES ANALYSIS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    echo -e "${YELLOW}[+] Binaries with Linux Capabilities${NC}"
    
    getcap -r / 2>/dev/null | while read line; do
        binary=$(echo "$line" | awk '{print $1}')
        caps=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}')
        
        echo -e "${CYAN}[>] $binary${NC}"
        echo -e "    Capabilities: $caps"
        
        # Analyze dangerous capabilities
        if echo "$caps" | grep -q "cap_dac_override"; then
            echo -e "    ${RED}[!] CRITICAL: CAP_DAC_OVERRIDE - can bypass file permissions${NC}"
        fi
        
        if echo "$caps" | grep -q "cap_setuid"; then
            echo -e "    ${RED}[!] CRITICAL: CAP_SETUID - can change UID${NC}"
        fi
        
        if echo "$caps" | grep -q "cap_sys_admin"; then
            echo -e "    ${RED}[!] CRITICAL: CAP_SYS_ADMIN - extensive system administration${NC}"
        fi
    done
}

environment_analysis() {
    echo -e "\n${GREEN}[*] ENVIRONMENT & CREDENTIAL ANALYSIS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    echo -e "${YELLOW}[+] Environment Variables - Credential/Config Leakage${NC}"
    
    # Environment variable analysis
    env | grep -E "(PASSWORD|SECRET|TOKEN|KEY|API)" | while read var; do
        echo -e "${RED}[!] Sensitive environment variable: $var${NC}"
    done
    
    echo -e "\n${YELLOW}[+] Command History Analysis${NC}"
    
    # History files analysis
    history_files=(
        "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.python_history"
        "/root/.bash_history" "/home/*/.bash_history"
    )
    
    for hist_pattern in "${history_files[@]}"; do
        find / -path "$hist_pattern" -type f 2>/dev/null | while read hist_file; do
            echo -e "${CYAN}[>] Analyzing: $hist_file${NC}"
            
            # Look for credentials in history
            if [ -r "$hist_file" ]; then
                grep -E "(password|passwd|secret|token|api)" "$hist_file" 2>/dev/null | head -5 | while read line; do
                    echo -e "    ${YELLOW}[!] Potential credential: $line${NC}"
                done
            fi
        done
    done
}

# Novel Attack Vectors
advanced_vectors() {
    echo -e "\n${GREEN}[*] ADVANCED ATTACK VECTORS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    echo -e "${YELLOW}[+] Container Escape Detection${NC}"
    
    # Check for container environment
    if [ -f /.dockerenv ]; then
        echo -e "${RED}[!] Docker container detected${NC}"
        
        # Check for dangerous Docker capabilities
        capsh --print | grep -E "(cap_sys_admin|cap_dac_override)" && \
        echo -e "${RED}[!] CRITICAL: Container has dangerous capabilities - escape possible${NC}"
        
        # Check for Docker socket access
        [ -S /var/run/docker.sock ] && \
        echo -e "${RED}[!] CRITICAL: Docker socket accessible - container escape possible${NC}"
    fi
    
    echo -e "\n${YELLOW}[+] Cron Job Analysis${NC}"
    
    # Cron job exploitation vectors
    cron_files=("/etc/crontab" "/etc/cron.d/*" "/var/spool/cron/crontabs/*")
    
    for cron_pattern in "${cron_files[@]}"; do
        find / -path "$cron_pattern" -type f 2>/dev/null | while read cron_file; do
            if [ -r "$cron_file" ]; then
                echo -e "${CYAN}[>] Cron file: $cron_file${NC}"
                
                # Look for cron jobs with relative paths (hijackable)
                grep -v "^#" "$cron_file" 2>/dev/null | grep -E "^[^/]" | while read job; do
                    echo -e "    ${RED}[!] Relative path in cron job: $job${NC}"
                done
                
                # Look for writable script paths in cron jobs
                grep -oE '/[^[:space:]]+\.(sh|py|pl)' "$cron_file" 2>/dev/null | while read script; do
                    if [ -w "$script" ]; then
                        echo -e "    ${RED}[!] CRITICAL: Writable cron script: $script${NC}"
                    fi
                done
            fi
        done
    done
    
    echo -e "\n${YELLOW}[+] Library Hijacking Vectors${NC}"
    
    # LD_PRELOAD and library path analysis
    echo -e "${CYAN}[>] Library paths and preload opportunities:${NC}"
    echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
    echo "LD_PRELOAD: $LD_PRELOAD"
    
    # Check for writable library directories
    echo "$LD_LIBRARY_PATH:/usr/lib:/lib:/usr/local/lib" | tr ':' '\n' | while read lib_dir; do
        if [ -d "$lib_dir" ] && [ -w "$lib_dir" ]; then
            echo -e "${RED}[!] CRITICAL: Writable library directory: $lib_dir${NC}"
        fi
    done
}

# Main execution
main() {
    echo -e "${GREEN}Starting Red-Core Advanced Enumeration...${NC}\n"
    
    system_recon
    suid_analysis
    process_enumeration
    network_analysis
    file_permissions
    capability_analysis
    environment_analysis
    advanced_vectors
    
    echo -e "\n${GREEN}[*] ENUMERATION COMPLETE${NC}"
    echo -e "${YELLOW}[!] Review highlighted items for privilege escalation opportunities${NC}"
    echo -e "${CYAN}[!] For authorized security testing only${NC}"
}

# Execute main function
main "$@"
