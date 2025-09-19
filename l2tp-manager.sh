#!/bin/bash

# L2TP Server Manager Script
# Auto Install & Configuration with Interactive Management
# Created for Ubuntu/Debian systems
#
# GitHub: https://github.com/safrinnetwork/
# Made by Mostech

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory automatically
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

# Integrity validation function
validate_script_integrity() {
    local script_content=$(cat "$0" 2>/dev/null)
    
    # Check for required credits and links
    local required_strings=(
        "Made by Mostech"
        "github.com/safrinnetwork"
        "GitHub: https://github.com/safrinnetwork/"
    )
    
    for required_string in "${required_strings[@]}"; do
        if ! echo "$script_content" | grep -q "$required_string"; then
            echo -e "${RED}=================== INTEGRITY ERROR ===================${NC}"
            echo -e "${RED}🚫 SCRIPT INTEGRITY VIOLATION DETECTED!${NC}"
            echo -e "${RED}Required credit information has been removed or modified.${NC}"
            echo -e "${YELLOW}Missing: $required_string${NC}"
            echo -e "${RED}====================================================${NC}"
            echo -e "${CYAN}Please restore the original script from:${NC}"
            echo -e "${BLUE}https://github.com/safrinnetwork/${NC}"
            echo -e "${RED}====================================================${NC}"
            exit 1
        fi
    done
    
    # Additional validation for header comment
    if ! head -n 10 "$0" | grep -q "GitHub: https://github.com/safrinnetwork/"; then
        echo -e "${RED}=================== INTEGRITY ERROR ===================${NC}"
        echo -e "${RED}🚫 SCRIPT HEADER INTEGRITY VIOLATION!${NC}"
        echo -e "${RED}Original author information has been tampered with.${NC}"
        echo -e "${RED}====================================================${NC}"
        echo -e "${CYAN}Please restore the original script from:${NC}"
        echo -e "${BLUE}https://github.com/safrinnetwork/${NC}"
        echo -e "${RED}====================================================${NC}"
        exit 1
    fi
    
    # Check for unauthorized modifications (e.g., changing author name)
    local suspicious_patterns=(
        "Made by [^M][a-zA-Z]"
        "Created by [^M][a-zA-Z]"
    )

    for pattern in "${suspicious_patterns[@]}"; do
        if echo "$script_content" | grep -E "$pattern" | grep -v "Mostech"; then
            echo -e "${RED}=================== INTEGRITY ERROR ===================${NC}"
            echo -e "${RED}🚫 UNAUTHORIZED AUTHOR MODIFICATION DETECTED!${NC}"
            echo -e "${RED}Script authorship has been illegally changed.${NC}"
            echo -e "${RED}====================================================${NC}"
            echo -e "${CYAN}Please restore the original script from:${NC}"
            echo -e "${BLUE}https://github.com/safrinnetwork/${NC}"
            echo -e "${RED}====================================================${NC}"
            exit 1
        fi
    done
    
    # Validate minimum occurrence count of required strings
    local mostech_count=$(echo "$script_content" | grep -c "Made by Mostech")
    local github_count=$(echo "$script_content" | grep -c "github.com/safrinnetwork")
    
    if [[ $mostech_count -lt 5 ]] || [[ $github_count -lt 5 ]]; then
        echo -e "${RED}=================== INTEGRITY ERROR ===================${NC}"
        echo -e "${RED}🚫 INSUFFICIENT CREDIT INFORMATION!${NC}"
        echo -e "${RED}Required author credits appear to have been partially removed.${NC}"
        echo -e "${YELLOW}Expected: At least 5 instances of each credit${NC}"
        echo -e "${YELLOW}Found: $mostech_count 'Made by Mostech', $github_count 'github.com/safrinnetwork'${NC}"
        echo -e "${RED}====================================================${NC}"
        echo -e "${CYAN}Please restore the original script from:${NC}"
        echo -e "${BLUE}https://github.com/safrinnetwork/${NC}"
        echo -e "${RED}====================================================${NC}"
        exit 1
    fi
    
    return 0
}

# Additional stealth protection layer
__verify_author() {
    local expected_hash="c5f77e0c7a3b4e5a2f1d9e8b6c4a7e9"  # Placeholder hash
    local current_credits=$(grep -c "Made by Mostech\|github.com/safrinnetwork" "$0")
    [[ $current_credits -lt 8 ]] && { echo -e "\n${RED}Authentication failed.${NC}\n" && exit 1; }
}

# Configuration files
L2TP_CONFIG="/etc/xl2tpd/xl2tpd.conf"
PPP_CONFIG="/etc/ppp/options.xl2tpd"
CHAP_SECRETS="/etc/ppp/chap-secrets"
FORWARDS_CONFIG="/etc/l2tp-forwards.conf"
SERVICE_FILE="/etc/systemd/system/l2tp-forwards.service"

# Input validation functions
validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        return 0
    fi
    return 1
}

validate_username() {
    local username="$1"
    if [[ $username =~ ^[a-zA-Z0-9_-]{3,32}$ ]]; then
        return 0
    fi
    return 1
}

validate_password() {
    local password="$1"
    if [[ ${#password} -ge 6 && ${#password} -le 64 ]]; then
        return 0
    fi
    return 1
}

validate_forward_name() {
    local name="$1"
    if [[ $name =~ ^[a-zA-Z0-9_-]{2,20}$ ]]; then
        return 0
    fi
    return 1
}

# Variable sanitization function
sanitize_input() {
    local input="$1"
    # Remove potentially dangerous characters
    echo "$input" | sed 's/[;&|`$(){}\\<>]//g'
}

# Generate random username
generate_random_username() {
    local prefixes=("user" "client" "vpn" "l2tp" "remote" "mobile" "laptop" "office" "home" "guest")
    local prefix=${prefixes[$RANDOM % ${#prefixes[@]}]}
    local number=$(printf "%04d" $((RANDOM % 10000)))
    echo "${prefix}${number}"
}

# Generate random password
generate_random_password() {
    local length=${1:-12}
    local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*"
    local password=""
    
    # Ensure at least one character from each category
    local uppers="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local lowers="abcdefghijklmnopqrstuvwxyz"
    local numbers="0123456789"
    local symbols="@#$%^&*"
    
    # Add one from each category
    password+=${uppers:$((RANDOM % ${#uppers})):1}
    password+=${lowers:$((RANDOM % ${#lowers})):1}
    password+=${numbers:$((RANDOM % ${#numbers})):1}
    password+=${symbols:$((RANDOM % ${#symbols})):1}
    
    # Fill the rest randomly
    for ((i=4; i<length; i++)); do
        password+=${chars:$((RANDOM % ${#chars})):1}
    done
    
    # Shuffle the password
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

# Check if username already exists
username_exists() {
    local username="$1"
    grep -q "^$username\s" "$CHAP_SECRETS" 2>/dev/null
}

# Get next available IP address
get_next_available_ip() {
    local base_ip="10.50.0"
    local start_range=10
    local end_range=100
    
    # Get all currently assigned IPs
    local assigned_ips=()
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ $line =~ ^#.*$ ]] || [[ -z $line ]] && continue
        
        # Extract IP from chap-secrets (4th column)
        local ip=$(echo "$line" | awk '{print $4}')
        if [[ $ip =~ ^10\.50\.0\.[0-9]+$ ]]; then
            local last_octet=${ip##*.}
            assigned_ips+=("$last_octet")
        fi
    done < "$CHAP_SECRETS"
    
    # Find next available IP
    for ((i=start_range; i<=end_range; i++)); do
        local ip_found=false
        for assigned in "${assigned_ips[@]}"; do
            if [[ "$assigned" == "$i" ]]; then
                ip_found=true
                break
            fi
        done
        
        if [[ "$ip_found" == false ]]; then
            echo "${base_ip}.${i}"
            return 0
        fi
    done
    
    # If no IP available, return error
    return 1
}

# Check if IP is already assigned
ip_already_assigned() {
    local check_ip="$1"
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ $line =~ ^#.*$ ]] || [[ -z $line ]] && continue
        
        local assigned_ip=$(echo "$line" | awk '{print $4}')
        if [[ "$assigned_ip" == "$check_ip" ]]; then
            return 0  # IP is already assigned
        fi
    done < "$CHAP_SECRETS"
    return 1  # IP is available
}

# Show current IP assignments
show_ip_assignments() {
    echo -e "${YELLOW}📊 Current IP Assignments:${NC}"
    echo -e "${CYAN}---------------------------------------${NC}"
    
    local count=0
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ $line =~ ^#.*$ ]] || [[ -z $line ]] && continue
        
        local username=$(echo "$line" | awk '{print $1}')
        local ip=$(echo "$line" | awk '{print $4}')
        
        if [[ "$ip" == "*" ]]; then
            echo -e "   ${username}: ${YELLOW}Auto-assign${NC}"
        else
            echo -e "   ${username}: ${GREEN}$ip${NC}"
        fi
        ((count++))
    done < "$CHAP_SECRETS"
    
    if [[ $count -eq 0 ]]; then
        echo -e "   ${YELLOW}No users configured${NC}"
    fi
    
    echo -e "${CYAN}---------------------------------------${NC}"
    
    # Show next available IP
    local next_ip
    if next_ip=$(get_next_available_ip); then
        echo -e "${GREEN}Next available IP: $next_ip${NC}"
    else
        echo -e "${RED}No available IPs in range 10.50.0.10-100${NC}"
    fi
    echo
}

# Generate random port in range 1000-9999
generate_random_port() {
    echo $((RANDOM % 9000 + 1000))
}

# Check if port is already in use (simplified and more reliable)
port_in_use() {
    local port="$1"
    
    # Validate port number
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        return 0  # Invalid port, consider as "in use"
    fi
    
    # Simple but effective check: try to bind to the port
    if ! nc -z localhost "$port" 2>/dev/null; then
        # Port is free if nc fails to connect
        return 1
    else
        # Port is in use if nc can connect
        return 0
    fi
}

# Generate unique random port (simplified)
generate_unique_port() {
    local max_attempts=50
    local attempt=0
    
    while (( attempt < max_attempts )); do
        local port=$(generate_random_port)
        
        # Check if port is available by testing connection
        if ! nc -z 127.0.0.1 "$port" 2>/dev/null && ! ss -tln | grep -q ":$port "; then
            echo "$port"
            return 0
        fi
        
        ((attempt++))
    done
    
    # If can't find unique port, return error
    error "Could not generate unique port after $max_attempts attempts"
    return 1
}

# Add port forward rule
add_port_forward_rule() {
    local name="$1"
    local ext_port="$2"
    local int_ip="$3"
    local int_port="$4"
    local description="$5"
    
    # Validate inputs
    if [[ -z "$name" ]] || [[ -z "$ext_port" ]] || [[ -z "$int_ip" ]] || [[ -z "$int_port" ]]; then
        error "Invalid parameters for port forward rule"
        return 1
    fi
    
    # Add forward to config
    local config_line="$name:$ext_port:$int_ip:$int_port:$description"
    if ! echo "$config_line" >> "$FORWARDS_CONFIG"; then
        error "Failed to add forward '$name' to configuration file"
        return 1
    fi
    
    # Add firewall rule
    if ! iptables -A INPUT -p tcp --dport "$ext_port" -j ACCEPT 2>/dev/null; then
        error "Failed to add firewall rule for port $ext_port"
        # Remove from config if firewall rule failed
        sed -i "/^$name:/d" "$FORWARDS_CONFIG"
        return 1
    fi
    
    # Start the forward
    echo -e "Starting socat for $name on port $ext_port..."
    
    # Test socat command first
    if ! command -v socat >/dev/null 2>&1; then
        error "Socat command not found. Please install socat."
        return 1
    fi
    
    # Start socat process in background with proper nohup
    nohup socat TCP4-LISTEN:"$ext_port",reuseaddr,fork TCP4:"$int_ip":"$int_port" >/dev/null 2>&1 &
    local socat_pid=$!
    
    # Wait a moment to ensure socat started
    sleep 2
    
    # Verify port is listening (more reliable check)
    local listening=false
    for i in {1..10}; do
        if ss -tln | grep -q ":${ext_port} "; then
            listening=true
            break
        fi
        sleep 1
    done
    
    if [[ "$listening" != "true" ]]; then
        # Double-check with netstat as backup
        if netstat -tln 2>/dev/null | grep -q ":${ext_port} "; then
            listening=true
        fi
    fi
    
    if [[ "$listening" != "true" ]]; then
        warning "Port $ext_port may not be listening properly, but process was started"
        # Don't fail completely - the process might still be starting
        info "Socat process started (PID: $socat_pid) - please verify manually if needed"
    else
        info "Socat process started successfully (PID: $socat_pid) and listening on port $ext_port"
    fi
    
    # Save iptables rules permanently
    if command -v iptables-save >/dev/null 2>&1; then
        if ! iptables-save > /etc/iptables/rules.v4 2>/dev/null; then
            warning "Forward created but firewall rules not saved permanently"
        else
            info "Firewall rule added and saved permanently"
        fi
    else
        warning "iptables-save not available - rules may not persist after reboot"
    fi
    
    return 0
}

# Create port forwards for user
create_user_port_forwards() {
    local username="$1"
    local user_ip="$2"
    
    # Validate inputs
    if [[ -z "$username" ]] || [[ -z "$user_ip" ]]; then
        error "Invalid parameters for port forward creation"
        return 1
    fi
    
    echo -e "\n${YELLOW}🔄 Creating Port Forwards for $username...${NC}"
    
    # Generate unique ports for Winbox (8291) and API (8728)
    local winbox_port api_port
    
    echo -e "${YELLOW}Generating unique ports...${NC}"
    
    if ! winbox_port=$(generate_unique_port); then
        error "Failed to generate unique port for Winbox"
        return 1
    fi
    
    if ! api_port=$(generate_unique_port); then
        error "Failed to generate unique port for API"
        return 1
    fi
    
    # Ensure ports are different
    local max_attempts=5
    local attempt=0
    while [[ "$winbox_port" == "$api_port" ]] && (( attempt < max_attempts )); do
        if ! api_port=$(generate_unique_port); then
            error "Failed to generate unique API port"
            return 1
        fi
        ((attempt++))
    done
    
    if [[ "$winbox_port" == "$api_port" ]]; then
        error "Could not generate different ports for Winbox and API"
        return 1
    fi
    
    echo -e "${CYAN}===============================================${NC}"
    echo -e "${YELLOW}🔄 Generated Port Forwards:${NC}"
    echo -e "   • Winbox: ${GREEN}$PUBLIC_IP:$winbox_port${NC} → ${GREEN}$user_ip:8291${NC}"
    echo -e "   • API:    ${GREEN}$PUBLIC_IP:$api_port${NC} → ${GREEN}$user_ip:8728${NC}"
    echo -e "${CYAN}===============================================${NC}"
    
    # Create port forwards
    local winbox_name="${username}-winbox"
    local api_name="${username}-api"
    
    echo -e "\n${YELLOW}Creating port forwards...${NC}"
    
    # Create Winbox forward
    echo -e "Creating Winbox forward: $winbox_name..."
    if add_port_forward_rule "$winbox_name" "$winbox_port" "$user_ip" "8291" "MikroTik Winbox for $username"; then
        log "Winbox forward created: $PUBLIC_IP:$winbox_port -> $user_ip:8291"
    else
        error "Failed to create Winbox forward"
        return 1
    fi
    
    # Create API forward
    echo -e "Creating API forward: $api_name..."
    if add_port_forward_rule "$api_name" "$api_port" "$user_ip" "8728" "MikroTik API for $username"; then
        log "API forward created: $PUBLIC_IP:$api_port -> $user_ip:8728"
    else
        error "Failed to create API forward"
        # Don't cleanup winbox forward since it succeeded
        warning "Winbox forward was created successfully but API forward failed"
        return 1
    fi
    
    echo -e "\n${GREEN}✓ Port forwards created successfully!${NC}"
    
    # Return the ports for display
    echo "$winbox_port,$api_port"
    return 0
}

# Safe command execution with error checking
exec_cmd() {
    local cmd="$1"
    local error_msg="$2"
    
    if ! eval "$cmd" 2>/dev/null; then
        error "${error_msg:-Command failed: $cmd}"
        return 1
    fi
    return 0
}

# Auto-detect network interface
get_default_interface() {
    # Try multiple methods to detect default interface
    local interface
    
    # Method 1: ip route
    interface=$(ip route | grep '^default' | head -n1 | sed 's/.*dev \([^ ]*\).*/\1/' 2>/dev/null)
    
    # Method 2: route command (fallback)
    if [[ -z "$interface" ]]; then
        interface=$(route -n | grep '^0.0.0.0' | head -n1 | awk '{print $8}' 2>/dev/null)
    fi
    
    # Method 3: check common interface names
    if [[ -z "$interface" ]]; then
        for iface in eth0 ens3 ens18 enp0s3 venet0; do
            if ip addr show "$iface" >/dev/null 2>&1; then
                interface="$iface"
                break
            fi
        done
    fi
    
    echo "$interface"
}

# Get system information
get_system_info() {
    # OS Information
    if [[ -f /etc/os-release ]]; then
        local os_info=$(grep "PRETTY_NAME" /etc/os-release | cut -d'"' -f2)
    elif [[ -f /etc/lsb-release ]]; then
        local os_info=$(grep "DISTRIB_DESCRIPTION" /etc/lsb-release | cut -d'"' -f2)
    else
        local os_info=$(uname -s)
    fi
    echo "OS:$os_info"
    
    # CPU Information
    local cpu_info=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^ *//')
    local cpu_cores=$(nproc)
    echo "CPU:$cpu_info ($cpu_cores cores)"
    
    # RAM Information
    local total_ram=$(free -h | grep "Mem:" | awk '{print $2}')
    local used_ram=$(free -h | grep "Mem:" | awk '{print $3}')
    local ram_percent=$(free | grep "Mem:" | awk '{printf "%.1f", ($3/$2)*100}')
    echo "RAM:$used_ram / $total_ram (${ram_percent}% used)"
    
    # Storage Information
    local storage_info=$(df -h / | tail -1 | awk '{print $3 " / " $2 " (" $5 " used)"}')
    echo "Storage:$storage_info"
}

# Get server public IP
get_public_ip() {
    local ip
    ip=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || \
         curl -s --connect-timeout 10 icanhazip.com 2>/dev/null || \
         curl -s --connect-timeout 10 ipecho.net/plain 2>/dev/null)
    
    if [[ -z "$ip" ]] || ! validate_ip "$ip"; then
        error "Failed to get public IP address"
        return 1
    fi
    echo "$ip"
}

PUBLIC_IP=$(get_public_ip)
DEFAULT_INTERFACE=$(get_default_interface)

if [[ -z "$PUBLIC_IP" ]]; then
    error "Cannot determine public IP. Please check internet connection."
    exit 1
fi

if [[ -z "$DEFAULT_INTERFACE" ]]; then
    error "Cannot determine default network interface."
    exit 1
fi

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root!"
        exit 1
    fi
}

# Install required packages
install_packages() {
    log "Installing required packages..."
    
    # Quick integrity revalidation
    if ! grep -q "Made by Mostech" "$0" || ! grep -q "github.com/safrinnetwork" "$0"; then
        error "Script integrity compromised during execution"
        exit 1
    fi
    
    if ! exec_cmd "apt update" "Failed to update package list"; then
        return 1
    fi
    
    local packages="xl2tpd ppp socat iptables-persistent curl"
    if ! exec_cmd "apt install -y $packages" "Failed to install required packages"; then
        error "Package installation failed. Please check your internet connection and try again."
        return 1
    fi
    
    log "Packages installed successfully"
    return 0
}

# Configure L2TP server
configure_l2tp() {
    log "Configuring L2TP server..."
    
    # Stealth integrity check
    [[ $(grep -c "Made by Mostech" "$0") -lt 5 ]] && exit 1
    
    # Backup original config
    [ -f "$L2TP_CONFIG" ] && cp "$L2TP_CONFIG" "${L2TP_CONFIG}.backup"
    
    # Validate interface detection
    if [[ -z "$DEFAULT_INTERFACE" ]]; then
        warning "Could not detect default interface automatically"
        echo -e "${YELLOW}📋 Available interfaces:${NC}"
        ip addr show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '
        echo -e "${CYAN}💡 Script will use generic configuration. Manual interface specification may be needed.${NC}"
    else
        info "Using detected interface: $DEFAULT_INTERFACE"
    fi
    
    # Create xl2tpd configuration - listen on all interfaces for better compatibility
    cat > "$L2TP_CONFIG" << EOF
[global]
port = 1701
access control = no

[lns default]
ip range = 10.50.0.10-10.50.0.100
local ip = 10.50.0.1
require chap = yes
refuse pap = yes
require authentication = yes
name = L2TPServer
ppp debug = yes
pppoptfile = $PPP_CONFIG
length bit = yes
EOF

    # Create PPP options
    cat > "$PPP_CONFIG" << EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
mtu 1410
mru 1410
nodefaultroute
debug
proxyarp
require-chap
refuse-pap
EOF

    # Initialize CHAP secrets if not exists
    if [ ! -f "$CHAP_SECRETS" ]; then
        cat > "$CHAP_SECRETS" << EOF
# Secrets for authentication using CHAP
# client        server  secret                  IP addresses
EOF
    fi
    
    log "L2TP configuration completed"
}

# Configure firewall and IP forwarding
configure_firewall() {
    log "Configuring firewall and IP forwarding..."
    
    # Enable IP forwarding
    if ! exec_cmd "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf" "Failed to configure IP forwarding"; then
        return 1
    fi
    
    if ! exec_cmd "sysctl -p" "Failed to apply sysctl settings"; then
        return 1
    fi
    
    # Configure iptables with detected interface
    local rules=(
        "iptables -t nat -A POSTROUTING -s 10.50.0.0/24 -o $DEFAULT_INTERFACE -j MASQUERADE"
        "iptables -A FORWARD -s 10.50.0.0/24 -j ACCEPT"
        "iptables -A FORWARD -d 10.50.0.0/24 -j ACCEPT"
        "iptables -A INPUT -p udp --dport 1701 -j ACCEPT"
    )
    
    for rule in "${rules[@]}"; do
        if ! exec_cmd "$rule" "Failed to apply iptables rule: $rule"; then
            return 1
        fi
    done
    
    # Save iptables rules
    if ! exec_cmd "mkdir -p /etc/iptables" "Failed to create iptables directory"; then
        return 1
    fi
    
    if ! exec_cmd "iptables-save > /etc/iptables/rules.v4" "Failed to save iptables rules"; then
        return 1
    fi
    
    log "Firewall configured successfully (using interface: $DEFAULT_INTERFACE)"
    return 0
}

# Start and enable services
start_services() {
    log "Starting L2TP services..."
    
    if ! exec_cmd "systemctl enable xl2tpd" "Failed to enable xl2tpd service"; then
        return 1
    fi
    
    # Try to start service
    if ! systemctl start xl2tpd; then
        warning "Initial xl2tpd start failed, attempting automatic fix..."
        
        # Check for binding issues in logs
        if journalctl -u xl2tpd --no-pager -l | grep -q "Unable to bind socket"; then
            info "Detected socket binding issue, applying fix..."
            
            # Apply configuration fix
            fix_xl2tpd_config
            
            # Try starting again
            if systemctl start xl2tpd; then
                info "xl2tpd started successfully after configuration fix"
            else
                error "xl2tpd still failed to start after fix attempt"
                warning "Please check configuration manually"
                return 1
            fi
        else
            error "xl2tpd failed to start for unknown reason"
            exec_cmd "journalctl -u xl2tpd --no-pager -l" "Service logs"
            return 1
        fi
    fi
    
    # Wait a moment and verify service is running
    sleep 2
    if systemctl is-active --quiet xl2tpd; then
        log "L2TP service started successfully"
        return 0
    else
        error "L2TP service failed to start properly"
        return 1
    fi
}

# Initialize forwards configuration
init_forwards_config() {
    if [ ! -f "$FORWARDS_CONFIG" ]; then
        cat > "$FORWARDS_CONFIG" << EOF
# L2TP Port Forwards Configuration
# Format: name:external_port:internal_ip:internal_port:description
# Example: winbox:8889:10.50.0.10:8291:MikroTik Winbox Access
EOF
    fi
}

# Check if L2TP is already installed and configured
check_installation_status() {
    local packages_installed=true
    local config_exists=true
    local service_enabled=true
    
    # Check required packages
    local required_packages=("xl2tpd" "ppp" "socat" "iptables-persistent" "curl")
    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            packages_installed=false
            break
        fi
    done
    
    # Check configuration files
    if [[ ! -f "$L2TP_CONFIG" ]] || [[ ! -f "$PPP_CONFIG" ]] || [[ ! -f "$CHAP_SECRETS" ]]; then
        config_exists=false
    fi
    
    # Check if service is enabled
    if ! systemctl is-enabled xl2tpd >/dev/null 2>&1; then
        service_enabled=false
    fi
    
    # Return status: 0=fully configured, 1=partially configured, 2=not configured
    if [[ "$packages_installed" == true ]] && [[ "$config_exists" == true ]] && [[ "$service_enabled" == true ]]; then
        return 0  # Fully configured
    elif [[ "$packages_installed" == true ]] || [[ "$config_exists" == true ]]; then
        return 1  # Partially configured
    else
        return 2  # Not configured
    fi
}

# Display installation status
show_installation_status() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}         L2TP Installation Status          ${NC}"
    echo -e "${BLUE}            Made by Mostech               ${NC}"
    echo -e "${PURPLE}        github.com/safrinnetwork        ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"
    
    check_installation_status
    local status=$?
    
    case $status in
        0)
            echo -e "${GREEN}✅ L2TP Server Status: FULLY CONFIGURED${NC}\n"
            echo -e "${YELLOW}📋 Current Configuration:${NC}"
            echo -e "   • Packages: ${GREEN}✅ All installed${NC}"
            echo -e "   • Config Files: ${GREEN}✅ All present${NC}"
            echo -e "   • Service: ${GREEN}✅ Enabled and configured${NC}"
            echo -e "   • Public IP: ${GREEN}$PUBLIC_IP${NC}"
            echo -e "   • Interface: ${GREEN}$DEFAULT_INTERFACE${NC}\n"
            
            local xl2tp_status=$(systemctl is-active xl2tpd 2>/dev/null)
            if [[ "$xl2tp_status" == "active" ]]; then
                echo -e "${GREEN}🟢 Service Status: RUNNING${NC}"
            else
                echo -e "${YELLOW}🟡 Service Status: STOPPED (but configured)${NC}"
            fi
            
            local user_count=$(grep -v "^#" "$CHAP_SECRETS" 2>/dev/null | grep -v "^$" | wc -l)
            echo -e "${CYAN}👥 Configured Users: $user_count${NC}"
            
            local forward_count=$(grep -v "^#" "$FORWARDS_CONFIG" 2>/dev/null | grep -v "^$" | wc -l)
            echo -e "${CYAN}🔄 Port Forwards: $forward_count${NC}\n"
            
            echo -e "${GREEN}✨ Your L2TP server is ready to use!${NC}"
            echo -e "${YELLOW}💡 You can manage users and port forwards from the main menu.${NC}\n"
            ;;
        1)
            echo -e "${YELLOW}⚠️  L2TP Server Status: PARTIALLY CONFIGURED${NC}\n"
            echo -e "${YELLOW}Some components are installed but configuration is incomplete.${NC}"
            echo -e "${CYAN}Would you like to complete the installation? (y/N): ${NC}"
            read -r complete_install
            if [[ $complete_install =~ ^[yY]$ ]]; then
                return 3  # Signal to proceed with installation
            fi
            ;;
        2)
            echo -e "${RED}❌ L2TP Server Status: NOT CONFIGURED${NC}\n"
            echo -e "${YELLOW}L2TP server is not installed or configured.${NC}"
            echo -e "${CYAN}Would you like to proceed with installation? (y/N): ${NC}"
            read -r proceed_install
            if [[ $proceed_install =~ ^[yY]$ ]]; then
                return 3  # Signal to proceed with installation
            fi
            ;;
    esac
    
    return $status
}

# Create forwards service
create_forwards_service() {
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=L2TP Port Forwards Manager
After=network.target xl2tpd.service
Requires=xl2tpd.service

[Service]
Type=forking
ExecStart=$SCRIPT_PATH start-forwards
ExecStop=$SCRIPT_PATH stop-forwards
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable l2tp-forwards
}

# Fix existing xl2tpd configuration for compatibility
fix_xl2tpd_config() {
    if [[ -f "$L2TP_CONFIG" ]]; then
        # Check if config has listen-addr that might cause binding issues
        if grep -q "listen-addr" "$L2TP_CONFIG"; then
            warning "Found potentially problematic listen-addr in xl2tpd config"
            
            # Create backup
            cp "$L2TP_CONFIG" "${L2TP_CONFIG}.backup-$(date +%s)"
            
            # Remove listen-addr line
            sed -i '/listen-addr/d' "$L2TP_CONFIG"
            info "Removed listen-addr from xl2tpd configuration for better compatibility"
            
            return 0
        fi
    fi
    return 1
}

# Update existing service with correct path
update_service_path() {
    if [[ -f "$SERVICE_FILE" ]]; then
        # Check if service file has wrong path
        if grep -q "ExecStart=/root/l2tp-manager.sh" "$SERVICE_FILE" || ! grep -q "ExecStart=$SCRIPT_PATH" "$SERVICE_FILE"; then
            echo -e "${YELLOW}📝 Updating service file with correct script path...${NC}"
            create_forwards_service
            systemctl daemon-reload
            echo -e "${GREEN}✅ Service path updated successfully${NC}"
        fi
    fi
}

# Start all port forwards
start_forwards() {
    log "Starting port forwards..."
    
    # Silent integrity verification
    [[ $(head -15 "$0" | grep -c "safrinnetwork") -eq 0 ]] && exit 1
    
    # Kill existing socat processes
    pkill -f "socat.*TCP4-LISTEN" 2>/dev/null
    sleep 1
    
    # Restore saved iptables rules if available
    if [[ -f /etc/iptables/rules.v4 ]]; then
        if command -v iptables-restore >/dev/null 2>&1; then
            iptables-restore < /etc/iptables/rules.v4 2>/dev/null || warning "Could not restore saved iptables rules"
        fi
    fi
    
    while IFS=':' read -r name ext_port int_ip int_port desc; do
        # Skip comments and empty lines
        [[ $name =~ ^#.*$ ]] || [[ -z $name ]] && continue
        
        # Ensure firewall rule exists for this port
        if ! iptables -C INPUT -p tcp --dport "$ext_port" -j ACCEPT 2>/dev/null; then
            if iptables -A INPUT -p tcp --dport "$ext_port" -j ACCEPT 2>/dev/null; then
                log "Added missing firewall rule for port $ext_port"
            else
                warning "Failed to add firewall rule for port $ext_port"
            fi
        fi
        
        # Start socat in background
        socat TCP4-LISTEN:"$ext_port",reuseaddr,fork TCP4:"$int_ip":"$int_port" &
        
        log "Started forward: $name ($PUBLIC_IP:$ext_port -> $int_ip:$int_port)"
    done < "$FORWARDS_CONFIG"
    
    # Save updated rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || warning "Could not save iptables rules"
    fi
}

# Diagnostic function for port forwarding issues
diagnose_port_access() {
    echo -e "\n${CYAN}🔍 Port Forwarding Diagnostic${NC}"
    echo -e "${CYAN}==============================${NC}\n"
    
    # Check if any forwards are configured
    local forward_count=$(grep -v "^#" "$FORWARDS_CONFIG" 2>/dev/null | grep -v "^$" | wc -l)
    if [[ $forward_count -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  No port forwards configured${NC}"
        return 0
    fi
    
    echo -e "${BLUE}📋 Checking configured port forwards:${NC}"
    while IFS=':' read -r name ext_port int_ip int_port desc; do
        [[ $name =~ ^#.*$ ]] || [[ -z $name ]] && continue
        
        echo -e "\n${CYAN}🔸 Checking $name (${PUBLIC_IP}:$ext_port → $int_ip:$int_port)${NC}"
        
        # Check if socat process is running
        if pgrep -f "TCP4-LISTEN:$ext_port" >/dev/null; then
            echo -e "  ✅ Socat process: Running"
        else
            echo -e "  ❌ Socat process: Not running"
        fi
        
        # Check if port is listening
        if ss -tln | grep -q ":${ext_port} "; then
            echo -e "  ✅ Port listening: Yes"
        else
            echo -e "  ❌ Port listening: No"
        fi
        
        # Check firewall rule
        if iptables -C INPUT -p tcp --dport "$ext_port" -j ACCEPT 2>/dev/null; then
            echo -e "  ✅ Firewall rule: Exists"
        else
            echo -e "  ❌ Firewall rule: Missing"
        fi
    done < "$FORWARDS_CONFIG"
    
    echo -e "\n${BLUE}💡 To fix issues, try:${NC}"
    echo -e "   • Menu [10] - Restart All Forwards"
    echo -e "   • Menu [11] - Start All Services"
    echo -e "   • Check VPS provider firewall settings"
}

# Stop all port forwards
stop_forwards() {
    log "Stopping port forwards..."
    pkill -f "socat.*TCP4-LISTEN" 2>/dev/null
}

# Add L2TP user with manual input
add_user_manual() {
    echo -e "\n${YELLOW}✏️  Manual User Entry...${NC}"
    local username password ip_addr
    
    # Get public IP for display
    local PUBLIC_IP=$(get_public_ip)
    
    # Username validation
    while true; do
        read -p "Enter username (3-32 chars, alphanumeric, _, -): " username
        username=$(sanitize_input "$username")
        
        if [[ -z "$username" ]]; then
            error "Username cannot be empty"
            continue
        fi
        
        if ! validate_username "$username"; then
            error "Invalid username. Use 3-32 characters (letters, numbers, _, -)"
            continue
        fi
        
        # Check if user already exists
        if username_exists "$username"; then
            error "User '$username' already exists!"
            continue
        fi
        break
    done
    
    # Password validation
    while true; do
        read -p "Enter password (6-64 chars): " password
        
        if [[ -z "$password" ]]; then
            error "Password cannot be empty"
            continue
        fi
        
        if ! validate_password "$password"; then
            error "Password must be 6-64 characters long"
            continue
        fi
        
        break
    done
    
    # Auto-assign next available static IP
    if ip_addr=$(get_next_available_ip); then
        info "Auto-assigned next available static IP: $ip_addr"
    else
        error "No available static IPs in range. Please check IP assignments."
        return 1
    fi
    
    # Port forwarding setup
    echo -e "\n${CYAN}🔄 Port Forwarding Setup:${NC}"
    echo -e "${YELLOW}Choose port forwarding option:${NC}"
    echo -e "   ${GREEN}[1]${NC} 🎯 Standard MikroTik (Winbox + API)"
    echo -e "   ${GREEN}[2]${NC} 🛠️  Custom ports"
    echo -e "   ${GREEN}[3]${NC} ⏭️  Skip port forwarding"
    echo
    echo -e "${YELLOW}Enter your choice (1-3): ${NC}"
    echo -ne "${GREEN}▶ ${NC}"
    read forward_choice
    
    local create_forwards=false
    local custom_ports=()
    
    case $forward_choice in
        1)
            create_forwards=true
            info "Will create standard MikroTik forwards (Winbox + API)"
            ;;
        2)
            echo -e "\n${YELLOW}Custom Port Setup:${NC}"
            echo "Enter ports to forward:"
            echo "• Single port: 22"
            echo "• Multiple ports: 22,80,443"
            echo "• With description: 22:SSH,80:HTTP,443:HTTPS"
            echo
            read -p "Enter ports: " port_input
            
            if [[ -n "$port_input" ]]; then
                # Split by comma and process each port
                IFS=',' read -ra port_array <<< "$port_input"
                for port_spec in "${port_array[@]}"; do
                    port_spec=$(echo "$port_spec" | xargs) # trim whitespace
                    
                    if [[ "$port_spec" =~ ^[0-9]+:[^:]+$ ]]; then
                        # Format: port:description
                        custom_ports+=("$port_spec")
                        local port_num=${port_spec%%:*}
                        local desc=${port_spec#*:}
                        echo "Added: Port $port_num ($desc)"
                    elif [[ "$port_spec" =~ ^[0-9]+$ ]]; then
                        # Format: just port number
                        if [[ "$port_spec" -ge 1 && "$port_spec" -le 65535 ]]; then
                            custom_ports+=("$port_spec:Port$port_spec")
                            echo "Added: Port $port_spec"
                        else
                            warning "Invalid port number: $port_spec (valid range: 1-65535)"
                        fi
                    else
                        warning "Invalid format: $port_spec"
                    fi
                done
                
                if [[ ${#custom_ports[@]} -gt 0 ]]; then
                    create_forwards=true
                    info "Will create ${#custom_ports[@]} custom port forward(s)"
                else
                    info "No valid ports specified"
                fi
            else
                info "No ports specified"
            fi
            ;;
        3)
            info "Skipping port forwarding setup"
            ;;
        *)
            warning "Invalid choice. Skipping port forwarding."
            ;;
    esac
    
    # Add user to system
    add_user_to_system "$username" "$password" "$ip_addr"
    
    # Handle port forwarding after user creation
    local winbox_port="" api_port="" custom_forward_info=""
    
    if [[ "$create_forwards" == "true" ]]; then
        echo -e "\n${YELLOW}Setting up port forwards...${NC}"
        
        if [[ $forward_choice -eq 1 ]]; then
            # Standard MikroTik forwards
            local port_info
            if port_info=$(create_user_port_forwards "$username" "$ip_addr" 2>&1); then
                # Extract port numbers from output
                local last_line=$(echo "$port_info" | tail -n1)
                if [[ "$last_line" =~ ^[0-9]+,[0-9]+$ ]]; then
                    IFS=',' read -r winbox_port api_port <<< "$last_line"
                fi
                info "Standard MikroTik port forwards created successfully"
            else
                warning "Failed to create standard port forwards. You can add them manually later."
            fi
        elif [[ $forward_choice -eq 2 && ${#custom_ports[@]} -gt 0 ]]; then
            # Custom port forwards
            local success_count=0
            local forward_details=()
            
            for port_spec in "${custom_ports[@]}"; do
                local int_port=${port_spec%%:*}
                local description=${port_spec#*:}
                local ext_port=$(generate_unique_port)
                local forward_name="${username}-${int_port}"
                
                if add_port_forward_rule "$forward_name" "$ext_port" "$ip_addr" "$int_port" "$description for $username"; then
                    forward_details+=("$ext_port:$int_port:$description")
                    ((success_count++))
                else
                    warning "Failed to create forward for port $int_port"
                fi
            done
            
            if [[ $success_count -gt 0 ]]; then
                info "Created $success_count custom port forward(s)"
                # Build custom forward info for display
                for detail in "${forward_details[@]}"; do
                    local ext_p=${detail%%:*}
                    local remaining=${detail#*:}
                    local int_p=${remaining%%:*}
                    local desc=${remaining#*:}
                    custom_forward_info+="\n   • $desc: $PUBLIC_IP:$ext_p → $ip_addr:$int_p"
                done
                
                # Restart port forwards service to include new rules
                ./l2tp-manager.sh stop-forwards >/dev/null 2>&1
                ./l2tp-manager.sh start-forwards >/dev/null 2>&1
            fi
        fi
    fi
    
    # Display enhanced connection details
    echo -e "\n${GREEN}✓ User Created Successfully!${NC}"
    echo -e "${CYAN}===============================================${NC}"
    echo -e "${YELLOW}📋 Connection Details:${NC}"
    echo -e "${CYAN}Server IP:   ${NC}$PUBLIC_IP"
    echo -e "${CYAN}L2TP Port:   ${NC}1701"
    echo -e "${CYAN}Username:    ${NC}$username"
    echo -e "${CYAN}Password:    ${NC}$password"
    echo -e "${CYAN}Static IP:   ${NC}$ip_addr"
    
    # Show port forwarding details if created
    if [[ -n "$winbox_port" && -n "$api_port" ]]; then
        echo -e "${CYAN}Port Forwards:${NC}"
        echo -e "   • Winbox: $PUBLIC_IP:$winbox_port → $ip_addr:8291"
        echo -e "   • API:    $PUBLIC_IP:$api_port → $ip_addr:8728"
    elif [[ -n "$custom_forward_info" ]]; then
        echo -e "${CYAN}Port Forwards:${NC}"
        echo -e "$custom_forward_info"
    fi
    
    echo -e "${CYAN}===============================================${NC}"
    echo -e "${PURPLE}💡 Save these credentials safely!${NC}"
}

# Add L2TP user with random generation
add_user_random() {
    local username password ip_addr create_forwards
    local max_attempts=10
    local attempt=0
    
    # Generate unique random username
    while true; do
        username=$(generate_random_username)
        if ! username_exists "$username"; then
            break
        fi
        
        ((attempt++))
        if (( attempt >= max_attempts )); then
            error "Failed to generate unique username after $max_attempts attempts"
            return 1
        fi
    done
    
    # Generate random password
    password=$(generate_random_password 12)
    
    # Auto-assign next available static IP
    if ip_addr=$(get_next_available_ip); then
        info "Auto-assigned next available static IP: $ip_addr"
    else
        error "No available static IPs in range. Using auto-assign."
        ip_addr="*"
    fi
    
    # Ask about port forwarding (only if we have static IP)
    if [[ "$ip_addr" != "*" ]]; then
        echo -e "\n${YELLOW}🔄 Port Forwarding Setup:${NC}"
        echo -e "Would you like to create port forwards for MikroTik access?"
        echo -e "   • Winbox (8291) - Random external port (1000-9999)"
        echo -e "   • API (8728) - Random external port (1000-9999)"
        echo
        echo -e "${YELLOW}Create port forwards? (Y/n): ${NC}"
        echo -ne "${GREEN}▶ ${NC}"
        read create_forwards
        
        # Default to Yes if empty or Y/y
        if [[ -z "$create_forwards" ]] || [[ $create_forwards =~ ^[yY]$ ]]; then
            create_forwards="yes"
        else
            create_forwards="no"
        fi
    else
        create_forwards="no"
        warning "Port forwards require static IP. Skipping port forward creation."
    fi
    
    echo -e "\n${YELLOW}🎲 Generated Credentials:${NC}"
    echo -e "${CYAN}===============================================${NC}"
    echo -e "Username: ${GREEN}$username${NC}"
    echo -e "Password: ${GREEN}$password${NC}"
    if [[ "$ip_addr" == "*" ]]; then
        echo -e "IP Mode:  ${YELLOW}Auto-assign (dynamic)${NC}"
    else
        echo -e "Static IP: ${GREEN}$ip_addr${NC}"
    fi
    if [[ "$create_forwards" == "yes" ]]; then
        echo -e "Forwards:  ${GREEN}Yes (Winbox + API)${NC}"
    else
        echo -e "Forwards:  ${YELLOW}No${NC}"
    fi
    echo -e "${CYAN}===============================================${NC}\n"
    
    # Confirm creation
    echo -e "${YELLOW}Do you want to create this user? (y/N): ${NC}"
    read -r confirm
    if [[ ! $confirm =~ ^[yY]$ ]]; then
        info "User creation cancelled"
        return 0
    fi
    
    # Add user first
    if ! add_user_to_system "$username" "$password" "$ip_addr"; then
        error "Failed to create user. Aborting."
        return 1
    fi
    
    # Create port forwards if requested and we have static IP
    if [[ "$create_forwards" == "yes" ]] && [[ "$ip_addr" != "*" ]]; then
        echo -e "\n${YELLOW}Attempting to create port forwards...${NC}"
        
        local port_info
        if port_info=$(create_user_port_forwards "$username" "$ip_addr" 2>&1); then
            local winbox_port api_port
            IFS=',' read -r winbox_port api_port <<< "$port_info"
            
            # Verify we got valid port numbers
            if [[ "$winbox_port" =~ ^[0-9]+$ ]] && [[ "$api_port" =~ ^[0-9]+$ ]]; then
                echo -e "\n${GREEN}✓ Complete Setup Finished!${NC}"
                echo -e "${CYAN}===============================================${NC}"
                echo -e "${YELLOW}📋 Final Connection Details:${NC}"
                echo -e "Server IP:     ${GREEN}$PUBLIC_IP${NC}"
                echo -e "Username:      ${GREEN}$username${NC}"
                echo -e "Password:      ${GREEN}$password${NC}"
                echo -e "Static IP:     ${GREEN}$ip_addr${NC}"
                echo -e "Winbox Access: ${GREEN}$PUBLIC_IP:$winbox_port${NC}"
                echo -e "API Access:    ${GREEN}$PUBLIC_IP:$api_port${NC}"
                echo -e "${CYAN}===============================================${NC}"
                echo -e "${YELLOW}💡 Save these details safely!${NC}"
            else
                warning "Port forward created but port numbers are invalid: '$port_info'"
            fi
        else
            error "Port forward setup failed. Debug info: $port_info"
            warning "User created successfully but port forwards could not be established."
        fi
    fi
    
    echo
}

# Common function to add user to system
add_user_to_system() {
    local username="$1"
    local password="$2"
    local ip_addr="$3"
    
    # Sanitize all inputs
    username=$(sanitize_input "$username")
    password=$(sanitize_input "$password")
    
    # Add user to chap-secrets with proper formatting
    # Format: username * password ip_address
    if ! printf "%-20s *       %-20s %s\n" "$username" "$password" "$ip_addr" >> "$CHAP_SECRETS"; then
        error "Failed to add user to configuration file"
        return 1
    fi
    
    # Verify the file is still readable
    if ! [ -r "$CHAP_SECRETS" ]; then
        error "Configuration file became unreadable"
        return 1
    fi
    
    log "User '$username' added successfully"
    
    # Restart xl2tpd to reload config - simplified approach
    echo -e "${YELLOW}🔄 Restarting L2TP service to apply changes...${NC}"
    
    # Use systemctl restart which handles stop/start automatically
    if systemctl restart xl2tpd; then
        sleep 2
        if systemctl is-active xl2tpd >/dev/null 2>&1; then
            echo -e "${GREEN}✅ L2TP service restarted successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  Service restart completed but status unclear. Check manually if needed.${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  User added successfully, but service restart failed.${NC}"
        echo -e "${CYAN}💡 You can manually restart with: systemctl restart xl2tpd${NC}"
        # Don't return error - user was successfully added
    fi
    return 0
}

# Main Add L2TP user function with choice
add_user() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}              Add L2TP User               ${NC}"
    echo -e "${BLUE}            Made by Mostech               ${NC}"
    echo -e "${PURPLE}        github.com/safrinnetwork        ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"
    
    echo -e "${YELLOW}Choose creation method:${NC}"
    echo -e "   ${GREEN}[1]${NC} 🎲 Generate Random Username & Password"
    echo -e "   ${GREEN}[2]${NC} ✏️  Manual Username & Password Entry"
    echo -e "   ${GREEN}[0]${NC} ← Back to Main Menu"
    echo
    echo -e "${YELLOW}✨ Enter your choice (0-2): ${NC}"
    echo -ne "${GREEN}▶ ${NC}"
    read choice
    
    case $choice in
        1)
            echo -e "\n${CYAN}🎲 Generating Random User...${NC}\n"
            add_user_random
            ;;
        2)
            echo -e "\n${CYAN}✏️  Manual User Entry...${NC}\n"
            add_user_manual
            ;;
        0)
            return 0
            ;;
        *)
            error "Invalid option. Please try again."
            ;;
    esac
}

# Delete L2TP user
delete_user() {
    echo -e "\n${CYAN}=== Delete L2TP User ===${NC}"
    
    # List current users with numbers
    echo -e "\n${YELLOW}Current users:${NC}"
    local users_list=$(grep -v "^#" "$CHAP_SECRETS" | grep -v "^$")
    if [[ -z "$users_list" ]]; then
        warning "No users found!"
        return 1
    fi
    
    echo "$users_list" | nl -w2 -s'. '
    
    echo -e "\n${CYAN}Options:${NC}"
    echo "1. Enter username(s) directly: username1,username2"
    echo "2. Enter number(s): 1,7,3"
    echo "3. Enter 0 to cancel"
    
    read -p "Enter selection: " selection
    
    # Handle cancellation
    if [[ "$selection" == "0" ]]; then
        info "Deletion cancelled"
        return 0
    fi
    
    local users_to_delete=()
    
    # Check if input contains only numbers and commas
    if [[ "$selection" =~ ^[0-9,]+$ ]]; then
        # Number-based selection
        IFS=',' read -ra numbers <<< "$selection"
        local total_users=$(echo "$users_list" | wc -l)
        
        for num in "${numbers[@]}"; do
            num=$(echo "$num" | xargs) # trim whitespace
            if [[ "$num" -gt 0 && "$num" -le "$total_users" ]]; then
                local username=$(echo "$users_list" | sed -n "${num}p" | awk '{print $1}')
                users_to_delete+=("$username")
            else
                warning "Invalid number: $num (valid range: 1-$total_users)"
            fi
        done
    else
        # Username-based selection
        IFS=',' read -ra usernames <<< "$selection"
        for username in "${usernames[@]}"; do
            username=$(echo "$username" | xargs) # trim whitespace
            if grep -q "^$username\s" "$CHAP_SECRETS"; then
                users_to_delete+=("$username")
            else
                warning "User '$username' not found!"
            fi
        done
    fi
    
    # Check if any valid users to delete
    if [[ ${#users_to_delete[@]} -eq 0 ]]; then
        error "No valid users selected for deletion!"
        return 1
    fi
    
    # Show users to be deleted with their associated port forwards
    echo -e "\n${YELLOW}Users to be deleted:${NC}"
    local total_forwards_to_delete=0
    for user in "${users_to_delete[@]}"; do
        # Get user IP
        local user_ip=$(grep "^$user\s" "$CHAP_SECRETS" | awk '{print $4}')
        echo "• $user (IP: $user_ip)"
        
        # Find associated port forwards by username pattern and IP
        local related_forwards=()
        if [[ -f "$FORWARDS_CONFIG" ]]; then
            # Find forwards by username pattern (e.g., username-winbox, username-api)
            while IFS=':' read -r name ext_port int_ip int_port desc; do
                [[ $name =~ ^#.*$ ]] || [[ -z $name ]] && continue
                if [[ "$name" =~ ^$user- ]] || [[ "$int_ip" == "$user_ip" ]]; then
                    related_forwards+=("$name:$ext_port:$int_ip:$int_port:$desc")
                fi
            done < "$FORWARDS_CONFIG"
        fi
        
        if [[ ${#related_forwards[@]} -gt 0 ]]; then
            echo "  Related port forwards:"
            for forward in "${related_forwards[@]}"; do
                local fname=$(echo "$forward" | cut -d':' -f1)
                local fext=$(echo "$forward" | cut -d':' -f2)
                local fint_ip=$(echo "$forward" | cut -d':' -f3)
                local fint_port=$(echo "$forward" | cut -d':' -f4)
                local fdesc=$(echo "$forward" | cut -d':' -f5)
                echo "    - $fname: $fext → $fint_ip:$fint_port ($fdesc)"
                ((total_forwards_to_delete++))
            done
        fi
    done
    
    if [[ $total_forwards_to_delete -gt 0 ]]; then
        echo -e "\n${CYAN}Total port forwards to be deleted: $total_forwards_to_delete${NC}"
    fi
    
    # Confirm deletion
    read -p "Are you sure you want to delete these ${#users_to_delete[@]} user(s)? (y/N): " confirm
    if [[ $confirm != [yY] ]]; then
        info "Deletion cancelled"
        return 0
    fi
    
    # Delete users and their port forwards
    local deleted_count=0
    local total_forwards_deleted=0
    
    for username in "${users_to_delete[@]}"; do
        # Get user IP before deletion
        local user_ip=$(grep "^$username\s" "$CHAP_SECRETS" | awk '{print $4}')
        
        # Delete from chap-secrets
        if sed -i "/^$username\s/d" "$CHAP_SECRETS"; then
            log "User '$username' deleted from authentication"
            
            # Delete associated port forwards by username pattern and IP
            local forwards_deleted=0
            if [[ -f "$FORWARDS_CONFIG" ]]; then
                # Find and delete forwards by username pattern
                if grep -q "^$username-" "$FORWARDS_CONFIG" 2>/dev/null; then
                    # Count forwards before deletion
                    local forwards_count=$(grep -c "^$username-" "$FORWARDS_CONFIG" 2>/dev/null || echo 0)
                    
                    # Get port numbers for cleanup before deletion
                    local ports_to_cleanup=()
                    while IFS=':' read -r name ext_port int_ip int_port desc; do
                        [[ $name =~ ^$username- ]] && ports_to_cleanup+=("$ext_port")
                    done < <(grep "^$username-" "$FORWARDS_CONFIG" 2>/dev/null)
                    
                    # Delete from config
                    sed -i "/^$username-/d" "$FORWARDS_CONFIG"
                    forwards_deleted=$((forwards_deleted + forwards_count))
                fi
                
                # Find and delete forwards by IP (for cases where forwards don't follow username pattern)
                if [[ -n "$user_ip" && "$user_ip" != "*" ]]; then
                    # Get forwards with matching IP that weren't caught by username pattern
                    local ip_forwards=()
                    while IFS=':' read -r name ext_port int_ip int_port desc; do
                        [[ $name =~ ^#.*$ ]] || [[ -z $name ]] && continue
                        if [[ "$int_ip" == "$user_ip" ]] && [[ ! "$name" =~ ^$username- ]]; then
                            ip_forwards+=("$name:$ext_port")
                        fi
                    done < "$FORWARDS_CONFIG"
                    
                    # Delete IP-based forwards
                    for forward_info in "${ip_forwards[@]}"; do
                        local fname=$(echo "$forward_info" | cut -d':' -f1)
                        local fport=$(echo "$forward_info" | cut -d':' -f2)
                        
                        # Stop socat process
                        pkill -f "TCP4-LISTEN:$fport" 2>/dev/null
                        
                        # Remove firewall rule
                        iptables -D INPUT -p tcp --dport "$fport" -j ACCEPT 2>/dev/null
                        
                        # Delete from config
                        sed -i "/^$fname:/d" "$FORWARDS_CONFIG"
                        ((forwards_deleted++))
                        log "Port forward '$fname' (IP: $user_ip) deleted"
                    done
                fi
                
                # Cleanup socat processes and firewall rules for username-based forwards
                for port in "${ports_to_cleanup[@]}"; do
                    [[ -n "$port" ]] || continue
                    pkill -f "TCP4-LISTEN:$port" 2>/dev/null
                    iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
                done
                
                if [[ $forwards_deleted -gt 0 ]]; then
                    log "Deleted $forwards_deleted port forward(s) for user '$username'"
                    total_forwards_deleted=$((total_forwards_deleted + forwards_deleted))
                fi
            fi
            
            ((deleted_count++))
        else
            error "Failed to delete user '$username'"
        fi
    done
    
    if [[ $deleted_count -gt 0 ]]; then
        info "Successfully deleted $deleted_count user(s)"
        
        if [[ $total_forwards_deleted -gt 0 ]]; then
            info "Successfully deleted $total_forwards_deleted related port forward(s)"
        fi
        
        # Restart services
        echo -e "\n${YELLOW}Restarting services...${NC}"
        systemctl restart xl2tpd
        
        # Restart port forwards if any remain or were deleted
        if [[ $total_forwards_deleted -gt 0 ]] || grep -q "^[^#]" "$FORWARDS_CONFIG" 2>/dev/null; then
            ./l2tp-manager.sh stop-forwards >/dev/null 2>&1
            ./l2tp-manager.sh start-forwards >/dev/null 2>&1
            info "Port forwarding service restarted"
        fi
        
        # Save iptables rules
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        
        info "All services restarted successfully"
    else
        error "No users were deleted"
    fi
}

# Edit L2TP user
edit_user() {
    echo -e "\n${CYAN}=== Edit L2TP User ===${NC}"
    
    # List current users
    echo -e "\n${YELLOW}Current users:${NC}"
    grep -v "^#" "$CHAP_SECRETS" | grep -v "^$" | nl
    
    read -p "Enter username to edit: " username
    
    # Check if user exists
    if ! grep -q "^$username\s" "$CHAP_SECRETS"; then
        error "User '$username' not found!"
        return 1
    fi
    
    # Get current user info
    current_line=$(grep "^$username\s" "$CHAP_SECRETS")
    current_pass=$(echo "$current_line" | awk '{print $3}')
    current_ip=$(echo "$current_line" | awk '{print $4}')
    
    echo -e "\nCurrent settings for '$username':"
    echo "Password: $current_pass"
    echo "IP: $current_ip"
    
    read -s -p "Enter new password (press enter to keep current): " new_password
    echo
    read -p "Enter new IP (press enter to keep current): " new_ip
    
    # Use current values if empty
    [ -z "$new_password" ] && new_password="$current_pass"
    [ -z "$new_ip" ] && new_ip="$current_ip"
    
    # Update user
    sed -i "/^$username\s/c\\$username        *       $new_password               $new_ip" "$CHAP_SECRETS"
    
    log "User '$username' updated successfully"
    
    # Restart xl2tpd to reload config
    systemctl restart xl2tpd
}

# List L2TP users
list_users() {
    echo -e "\n${CYAN}=== L2TP Users ===${NC}"
    
    # Get public IP
    local PUBLIC_IP=$(get_public_ip)
    
    # Check if there are any users
    local users_exist=false
    while read -r line; do
        [[ $line =~ ^#.*$ ]] || [[ -z $line ]] && continue
        users_exist=true
        break
    done < "$CHAP_SECRETS"
    
    if [[ "$users_exist" != "true" ]]; then
        warning "No L2TP users found!"
        return 1
    fi
    
    echo -e "\n${YELLOW}Server Public IP:${NC} $PUBLIC_IP"
    echo -e "${YELLOW}L2TP Port:${NC} 1701"
    echo
    
    local user_count=0
    while read -r line; do
        # Skip comments and empty lines
        [[ $line =~ ^#.*$ ]] || [[ -z $line ]] && continue
        
        ((user_count++))
        username=$(echo "$line" | awk '{print $1}')
        password=$(echo "$line" | awk '{print $3}')
        ip_addr=$(echo "$line" | awk '{print $4}')
        
        echo -e "${CYAN}[$user_count] User: ${GREEN}$username${NC}"
        echo -e "    Password: ${GREEN}$password${NC}"
        echo -e "    Internal IP: ${GREEN}$ip_addr${NC}"
        
        # Find related port forwards
        local forwards_found=false
        if [[ -f "$FORWARDS_CONFIG" ]]; then
            echo -e "    Port Forwards:"
            while IFS=':' read -r name ext_port int_ip int_port desc; do
                [[ $name =~ ^#.*$ ]] || [[ -z $name ]] && continue
                
                # Check if forward is related to this user (by username pattern or IP)
                if [[ "$name" =~ ^$username- ]] || [[ "$int_ip" == "$ip_addr" ]]; then
                    echo -e "      • ${YELLOW}$name${NC}: $PUBLIC_IP:${GREEN}$ext_port${NC} → $int_ip:$int_port ${PURPLE}($desc)${NC}"
                    forwards_found=true
                fi
            done < "$FORWARDS_CONFIG"
            
            if [[ "$forwards_found" != "true" ]]; then
                echo -e "      ${YELLOW}No port forwards configured${NC}"
            fi
        else
            echo -e "      ${YELLOW}No port forwards configured${NC}"
        fi
        
        echo
    done < "$CHAP_SECRETS"
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Total Users: ${GREEN}$user_count${NC}"
    
    # Count total port forwards
    local total_forwards=0
    if [[ -f "$FORWARDS_CONFIG" ]]; then
        while IFS=':' read -r name ext_port int_ip int_port desc; do
            [[ $name =~ ^#.*$ ]] || [[ -z $name ]] && continue
            ((total_forwards++))
        done < "$FORWARDS_CONFIG"
    fi
    
    echo -e "${YELLOW}Total Port Forwards: ${GREEN}$total_forwards${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

# Add port forward
add_forward() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}            Add Port Forward             ${NC}"
    echo -e "${BLUE}            Made by Mostech               ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"
    
    local name ext_port int_ip int_port description
    
    # Forward name validation
    while true; do
        read -p "Enter forward name (2-20 chars, alphanumeric, _, -): " name
        name=$(sanitize_input "$name")
        
        if [[ -z "$name" ]]; then
            error "Forward name cannot be empty"
            continue
        fi
        
        if ! validate_forward_name "$name"; then
            error "Invalid forward name. Use 2-20 characters (letters, numbers, _, -)"
            continue
        fi
        
        # Check if forward already exists
        if grep -q "^$name:" "$FORWARDS_CONFIG"; then
            error "Forward '$name' already exists!"
            continue
        fi
        break
    done
    
    # External port validation
    while true; do
        read -p "Enter external port (1-65535): " ext_port
        ext_port=$(sanitize_input "$ext_port")
        
        if ! validate_port "$ext_port"; then
            error "Invalid port number. Use 1-65535"
            continue
        fi
        
        # Check if port is already in use
        if netstat -tuln 2>/dev/null | grep -q ":$ext_port "; then
            error "Port $ext_port is already in use"
            continue
        fi
        break
    done
    
    # Internal IP validation
    while true; do
        read -p "Enter internal IP address: " int_ip
        int_ip=$(sanitize_input "$int_ip")
        
        if ! validate_ip "$int_ip"; then
            error "Invalid IP address format"
            continue
        fi
        break
    done
    
    # Internal port validation
    while true; do
        read -p "Enter internal port (1-65535): " int_port
        int_port=$(sanitize_input "$int_port")
        
        if ! validate_port "$int_port"; then
            error "Invalid port number. Use 1-65535"
            continue
        fi
        break
    done
    
    # Description (optional, sanitized)
    read -p "Enter description (optional): " description
    description=$(sanitize_input "$description")
    [[ -z "$description" ]] && description="Port forward for $name"
    
    # Add forward to config
    local config_line="$name:$ext_port:$int_ip:$int_port:$description"
    if ! echo "$config_line" >> "$FORWARDS_CONFIG"; then
        error "Failed to add forward to configuration file"
        return 1
    fi
    
    # Add firewall rule
    if ! exec_cmd "iptables -A INPUT -p tcp --dport $ext_port -j ACCEPT" "Failed to add firewall rule"; then
        # Remove from config if firewall rule failed
        sed -i "/^$name:/d" "$FORWARDS_CONFIG"
        return 1
    fi
    
    # Start the forward
    if ! socat TCP4-LISTEN:"$ext_port",reuseaddr,fork TCP4:"$int_ip":"$int_port" & then
        error "Failed to start port forward"
        # Cleanup
        sed -i "/^$name:/d" "$FORWARDS_CONFIG"
        iptables -D INPUT -p tcp --dport "$ext_port" -j ACCEPT 2>/dev/null
        return 1
    fi
    
    log "Forward '$name' added and started ($PUBLIC_IP:$ext_port -> $int_ip:$int_port)"
    
    # Save iptables rules
    if ! exec_cmd "iptables-save > /etc/iptables/rules.v4" "Failed to save firewall rules"; then
        warning "Forward created but firewall rules not saved permanently"
    fi
    
    return 0
}

# Delete port forward
delete_forward() {
    echo -e "\n${CYAN}=== Delete Port Forward ===${NC}"
    
    # Get all forwards excluding comments and empty lines
    local forwards_list=$(grep -v "^#" "$FORWARDS_CONFIG" | grep -v "^$")
    if [[ -z "$forwards_list" ]]; then
        warning "No port forwards found!"
        return 1
    fi
    
    # Display numbered list
    echo -e "\n${YELLOW}Current port forwards:${NC}"
    local counter=1
    while IFS=':' read -r name ext_port int_ip int_port desc; do
        [[ -z "$name" ]] && continue
        printf "%2d. %-15s %-10s %-15s %s\n" "$counter" "$name" "$ext_port" "$int_ip:$int_port" "$desc"
        ((counter++))
    done <<< "$forwards_list"
    
    echo -e "\n${CYAN}Options:${NC}"
    echo "1. Enter forward name(s) directly: name1,name2"
    echo "2. Enter number(s): 1,3,5"
    echo "3. Enter 0 to cancel"
    
    read -p "Enter selection: " selection
    
    # Handle cancellation
    if [[ "$selection" == "0" ]]; then
        info "Deletion cancelled"
        return 0
    fi
    
    local forwards_to_delete=()
    
    # Check if input contains only numbers and commas
    if [[ "$selection" =~ ^[0-9,]+$ ]]; then
        # Number-based selection
        IFS=',' read -ra numbers <<< "$selection"
        local total_forwards=$(echo "$forwards_list" | wc -l)
        
        for num in "${numbers[@]}"; do
            num=$(echo "$num" | xargs) # trim whitespace
            if [[ "$num" -gt 0 && "$num" -le "$total_forwards" ]]; then
                local forward_line=$(echo "$forwards_list" | sed -n "${num}p")
                local forward_name=$(echo "$forward_line" | cut -d':' -f1)
                forwards_to_delete+=("$forward_name")
            else
                warning "Invalid number: $num (valid range: 1-$total_forwards)"
            fi
        done
    else
        # Name-based selection
        IFS=',' read -ra forward_names <<< "$selection"
        for name in "${forward_names[@]}"; do
            name=$(echo "$name" | xargs) # trim whitespace
            if grep -q "^$name:" "$FORWARDS_CONFIG"; then
                forwards_to_delete+=("$name")
            else
                warning "Forward '$name' not found!"
            fi
        done
    fi
    
    # Check if any valid forwards to delete
    if [[ ${#forwards_to_delete[@]} -eq 0 ]]; then
        error "No valid forwards selected for deletion!"
        return 1
    fi
    
    # Show forwards to be deleted with details
    echo -e "\n${YELLOW}Forwards to be deleted:${NC}"
    for name in "${forwards_to_delete[@]}"; do
        local forward_info=$(grep "^$name:" "$FORWARDS_CONFIG")
        local ext_port=$(echo "$forward_info" | cut -d':' -f2)
        local int_ip=$(echo "$forward_info" | cut -d':' -f3)
        local int_port=$(echo "$forward_info" | cut -d':' -f4)
        local desc=$(echo "$forward_info" | cut -d':' -f5)
        echo "• $name: $ext_port → $int_ip:$int_port ($desc)"
    done
    
    # Confirm deletion
    read -p "Are you sure you want to delete these ${#forwards_to_delete[@]} forward(s)? (y/N): " confirm
    if [[ $confirm != [yY] ]]; then
        info "Deletion cancelled"
        return 0
    fi
    
    # Delete forwards
    local deleted_count=0
    for name in "${forwards_to_delete[@]}"; do
        # Get port number for cleanup
        local ext_port=$(grep "^$name:" "$FORWARDS_CONFIG" | cut -d':' -f2)
        
        if [[ -n "$ext_port" ]]; then
            # Stop the socat process
            pkill -f "TCP4-LISTEN:$ext_port" 2>/dev/null
            
            # Remove firewall rule
            iptables -D INPUT -p tcp --dport "$ext_port" -j ACCEPT 2>/dev/null
            
            # Delete forward from config
            if sed -i "/^$name:/d" "$FORWARDS_CONFIG"; then
                log "Forward '$name' deleted successfully"
                ((deleted_count++))
            else
                error "Failed to delete forward '$name'"
            fi
        fi
    done
    
    if [[ $deleted_count -gt 0 ]]; then
        info "Successfully deleted $deleted_count forward(s)"
        
        # Save iptables rules
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        
        # Restart port forwards service if there are remaining forwards
        if grep -q "^[^#]" "$FORWARDS_CONFIG" 2>/dev/null; then
            echo -e "\n${YELLOW}Restarting port forwarding service...${NC}"
            ./l2tp-manager.sh stop-forwards >/dev/null 2>&1
            ./l2tp-manager.sh start-forwards >/dev/null 2>&1
            info "Port forwarding service restarted"
        fi
    else
        error "No forwards were deleted"
    fi
}

# List port forwards
list_forwards() {
    echo -e "\n${CYAN}=== Port Forwards ===${NC}"
    
    echo -e "\n${YELLOW}Name${NC}           ${YELLOW}External${NC}    ${YELLOW}Internal${NC}           ${YELLOW}Description${NC}"
    echo "----------------------------------------------------------------"
    
    while IFS=':' read -r name ext_port int_ip int_port desc; do
        # Skip comments and empty lines
        [[ $name =~ ^#.*$ ]] || [[ -z $name ]] && continue
        
        printf "%-15s %-10s %-15s %s\n" "$name" "$ext_port" "$int_ip:$int_port" "$desc"
    done < "$FORWARDS_CONFIG"
}

# Enhanced status display
show_status() {
    clear
    echo -e "\n${CYAN}===============================================================${NC}"
    echo -e "${CYAN}                     📊 Server Status                       ${NC}"
    echo -e "${BLUE}                      Made by Mostech                       ${NC}"
    echo -e "${PURPLE}                  github.com/safrinnetwork                 ${NC}"
    echo -e "${CYAN}===============================================================${NC}"
    echo
    
    # Server Information Section
    echo -e "${YELLOW}🌐 Server Information${NC}"
    echo -e "   Public IP:      ${GREEN}$PUBLIC_IP${NC}"
    echo -e "   Interface:      ${GREEN}$DEFAULT_INTERFACE${NC}"
    echo -e "   L2TP Port:      ${GREEN}1701/UDP${NC}"
    echo -e "   VPN Network:    ${GREEN}10.50.0.0/24${NC}"
    echo -e "   IP Range:       ${GREEN}10.50.0.10 - 10.50.0.100${NC}"
    echo -e "   Gateway:        ${GREEN}10.50.0.1${NC}"
    echo
    
    # Service Status Section
    echo -e "${YELLOW}⚙️  Service Status${NC}"
    
    local xl2tp_status=$(systemctl is-active xl2tpd 2>/dev/null)
    local xl2tp_enabled=$(systemctl is-enabled xl2tpd 2>/dev/null)
    if [[ "$xl2tp_status" == "active" ]]; then
        echo -e "   L2TP Service:   ${GREEN}🟢 Running${NC} (${GREEN}$xl2tp_enabled${NC})"
    else
        echo -e "   L2TP Service:   ${RED}🔴 Stopped${NC} (${RED}$xl2tp_enabled${NC})"
    fi
    
    local forward_status=$(systemctl is-active l2tp-forwards 2>/dev/null)
    local forward_enabled=$(systemctl is-enabled l2tp-forwards 2>/dev/null)
    if [[ "$forward_status" == "active" ]]; then
        echo -e "   Forward Service:${GREEN}🟢 Running${NC} (${GREEN}$forward_enabled${NC})"
    else
        echo -e "   Forward Service:${RED}🔴 Stopped${NC} (${RED}$forward_enabled${NC})"
    fi
    echo
    
    # Connection Statistics
    echo -e "${YELLOW}📊 Connection Statistics${NC}"
    
    local ppp_count=0
    if [ -d /var/run/xl2tpd ]; then
        ppp_count=$(ip addr show 2>/dev/null | grep "ppp" | wc -l)
    fi
    echo -e "   Active L2TP:    ${GREEN}$ppp_count${NC} client(s) connected"
    
    local socat_count=$(ps aux 2>/dev/null | grep "socat.*TCP4-LISTEN" | grep -v grep | wc -l)
    echo -e "   Port Forwards:  ${GREEN}$socat_count${NC} active forward(s)"
    
    local user_count=$(grep -v "^#" "$CHAP_SECRETS" 2>/dev/null | grep -v "^$" | wc -l)
    echo -e "   Configured:     ${GREEN}$user_count${NC} user(s), ${GREEN}$(grep -v "^#" "$FORWARDS_CONFIG" 2>/dev/null | grep -v "^$" | wc -l)${NC} forward(s)"
    echo
    
    # System Resources
    echo -e "${YELLOW}💻 System Resources${NC}"
    
    local uptime_info=$(uptime | cut -d',' -f1 | cut -d' ' -f4-)
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1 | xargs)
    echo -e "   Uptime:         ${GREEN}$uptime_info${NC}"
    echo -e "   Load Average:   ${GREEN}$load_avg${NC}"
    
    if command -v free >/dev/null 2>&1; then
        local mem_usage=$(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')
        echo -e "   Memory Usage:   ${GREEN}$mem_usage${NC}"
    fi
    echo
    
    echo -e "${CYAN}===============================================================${NC}"
    
    # Recent logs if service is running
    if [[ "$xl2tp_status" == "active" ]]; then
        echo -e "\n${YELLOW}📝 Recent L2TP Activity (last 5 entries):${NC}"
        echo -e "${CYAN}---------------------------------------------------------------${NC}"
        journalctl -u xl2tpd --no-pager -n 5 -o short 2>/dev/null | sed 's/^/   /' || echo "   No recent activity"
    fi
    
    echo
}

# Enhanced menu display
show_menu() {
    clear
    
    # Runtime protection
    ! grep -q "Made by Mostech" "$0" && exit 1
    
    # Header with enhanced styling
    echo -e "${CYAN}===============================================================${NC}"
    echo -e "${CYAN}                🚀 L2TP VPN Server Manager 🚀               ${NC}"
    echo -e "${CYAN}                     Professional Edition                     ${NC}"
    echo -e "${BLUE}                      Made by Mostech                       ${NC}"
    echo -e "${CYAN}===============================================================${NC}"
    echo
    
    # Server info section
    local xl2tp_status=$(systemctl is-active xl2tpd 2>/dev/null)
    local forward_status=$(systemctl is-active l2tp-forwards 2>/dev/null)
    local user_count=$(grep -v "^#" "$CHAP_SECRETS" 2>/dev/null | grep -v "^$" | wc -l)
    local forward_count=$(grep -v "^#" "$FORWARDS_CONFIG" 2>/dev/null | grep -v "^$" | wc -l)
    
    echo -e "${YELLOW}📊 Server Status:${NC}"
    echo -e "   • Public IP: ${GREEN}$PUBLIC_IP${NC}"
    echo -e "   • Interface: ${GREEN}$DEFAULT_INTERFACE${NC}"
    
    if [[ "$xl2tp_status" == "active" ]]; then
        echo -e "   • L2TP Service: ${GREEN}🟢 Running${NC}"
    else
        echo -e "   • L2TP Service: ${RED}🔴 Stopped${NC}"
    fi
    
    if [[ "$forward_status" == "active" ]]; then
        echo -e "   • Forwards: ${GREEN}🟢 Active${NC}"
    else
        echo -e "   • Forwards: ${RED}🔴 Inactive${NC}"
    fi
    
    echo -e "   • Users: ${CYAN}$user_count${NC} configured"
    echo -e "   • Port Forwards: ${CYAN}$forward_count${NC} configured"
    echo
    
    # System Information
    echo -e "${YELLOW}💻 System Information:${NC}"
    local system_info=$(get_system_info)
    while IFS=':' read -r key value; do
        case "$key" in
            "OS")
                echo -e "   • OS: ${GREEN}$value${NC}"
                ;;
            "CPU")
                echo -e "   • CPU: ${GREEN}$value${NC}"
                ;;
            "RAM")
                echo -e "   • RAM: ${GREEN}$value${NC}"
                ;;
            "Storage")
                echo -e "   • Storage: ${GREEN}$value${NC}"
                ;;
        esac
    done <<< "$system_info"
    
    echo
    echo -e "${CYAN}===============================================================${NC}"
    echo
    
    # Menu sections with icons and colors
    echo -e "${CYAN}🔧 INSTALLATION & STATUS${NC}"
    echo -e "   ${GREEN}[1]${NC}  🚀 Install & Configure L2TP Server"
    echo -e "   ${GREEN}[2]${NC}  📊 Show Detailed Server Status"
    echo
    echo -e "${CYAN}👥 USER MANAGEMENT${NC}"
    echo -e "   ${GREEN}[3]${NC}  ➕ Add New L2TP User"
    echo -e "   ${GREEN}[4]${NC}  ❌ Delete L2TP User"
    echo -e "   ${GREEN}[5]${NC}  ✏️ Edit L2TP User"
    echo -e "   ${GREEN}[6]${NC}  📋 List All L2TP Users"
    echo
    echo -e "${CYAN}🔀 PORT FORWARDING${NC}"
    echo -e "   ${GREEN}[7]${NC}  ➕ Add Port Forward Rule"
    echo -e "   ${GREEN}[8]${NC}  ❌ Delete Port Forward"
    echo -e "   ${GREEN}[9]${NC}  📋 List Active Forwards"
    echo -e "   ${GREEN}[10]${NC} 🔄 Restart All Forwards"
    echo
    echo -e "${CYAN}⚙️  SERVICE CONTROL${NC}"
    echo -e "   ${GREEN}[11]${NC} ✅ Start All Services"
    echo -e "   ${GREEN}[12]${NC} ⏹️ Stop All Services"
    echo -e "   ${GREEN}[13]${NC} 🔄 Restart All Services"
    echo
    echo -e "   ${RED}[0]${NC}  🚪 Exit Program"
    echo
    echo -e "${CYAN}===============================================================${NC}"
    echo -e "${YELLOW}💡 Tip: Use Ctrl+C to cancel any operation${NC}"
    echo -e "${PURPLE}🔗 GitHub: https://github.com/safrinnetwork/${NC}"
    echo
}

# Handle command line arguments
case "$1" in
    "start-forwards")
        start_forwards
        exit 0
        ;;
    "stop-forwards")
        stop_forwards
        exit 0
        ;;
esac

# Validate script integrity first
validate_script_integrity

# Check root
check_root

# Initialize configs
init_forwards_config

# Update service path if needed (for existing installations)
update_service_path

# Fix xl2tpd configuration if needed (for VPS compatibility)
if fix_xl2tpd_config; then
    echo -e "${GREEN}✅ Applied xl2tpd compatibility fix${NC}"
fi

# Ensure netfilter-persistent is configured for iptables persistence
if systemctl is-enabled netfilter-persistent >/dev/null 2>&1; then
    systemctl enable netfilter-persistent 2>/dev/null
fi

# Main loop
while true; do
    __verify_author  # Hidden call
    show_menu
    echo -e "${YELLOW}✨ Enter your choice (0-13): ${NC}"
    echo -ne "${GREEN}▶ ${NC}"
    read choice
    
    case $choice in
        1)
            show_installation_status
            install_status=$?
            
            if [[ $install_status -eq 0 ]]; then
                # Already fully configured - no installation needed
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read
            elif [[ $install_status -eq 3 ]]; then
                # User chose to proceed with installation
                echo -e "\n${YELLOW}🚀 Starting L2TP Server Installation...${NC}\n"
                
                if install_packages && configure_l2tp && configure_firewall && start_services && create_forwards_service; then
                    echo -e "\n${GREEN}✓ L2TP Server installation completed successfully!${NC}"
                    echo -e "${GREEN}✓ Server IP: $PUBLIC_IP:1701${NC}"
                    echo -e "${GREEN}✓ Interface: $DEFAULT_INTERFACE${NC}"
                    echo -e "${GREEN}✓ You can now add users and configure port forwards${NC}"
                else
                    echo -e "\n${RED}✗ Installation failed! Please check the logs and try again.${NC}"
                fi
                
                echo -e "\n${CYAN}Press Enter to continue...${NC}"
                read
            else
                # User chose not to proceed
                echo -e "\n${YELLOW}Installation cancelled by user.${NC}"
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read
            fi
            ;;
        2)
            show_status
            diagnose_port_access
            read -p "Press Enter to continue..."
            ;;
        3)
            add_user
            read -p "Press Enter to continue..."
            ;;
        4)
            delete_user
            read -p "Press Enter to continue..."
            ;;
        5)
            edit_user
            read -p "Press Enter to continue..."
            ;;
        6)
            list_users
            read -p "Press Enter to continue..."
            ;;
        7)
            add_forward
            read -p "Press Enter to continue..."
            ;;
        8)
            delete_forward
            read -p "Press Enter to continue..."
            ;;
        9)
            list_forwards
            read -p "Press Enter to continue..."
            ;;
        10)
            log "Restarting port forwards..."
            stop_forwards
            sleep 2
            start_forwards
            log "Port forwards restarted"
            read -p "Press Enter to continue..."
            ;;
        11)
            log "Starting services..."
            systemctl start xl2tpd
            systemctl start l2tp-forwards
            log "Services started"
            read -p "Press Enter to continue..."
            ;;
        12)
            log "Stopping services..."
            systemctl stop xl2tpd
            systemctl stop l2tp-forwards
            stop_forwards
            log "Services stopped"
            read -p "Press Enter to continue..."
            ;;
        13)
            log "Restarting services..."
            systemctl restart xl2tpd
            systemctl restart l2tp-forwards
            log "Services restarted"
            read -p "Press Enter to continue..."
            ;;
        0)
            clear
            echo -e "\n${CYAN}===============================================${NC}"
            echo -e "${CYAN}   🚀 Thank you for using L2TP Manager!   ${NC}"
            echo -e "${CYAN}                                               ${NC}"
            echo -e "${CYAN}      💻 Professional VPN Solution          ${NC}"
            echo -e "${CYAN}        Stay secure, stay connected!        ${NC}"
            echo -e "${CYAN}                                               ${NC}"
            echo -e "${BLUE}            Made by Mostech                 ${NC}"
            echo -e "${CYAN}===============================================${NC}\n"
            exit 0
            ;;
        *)
            error "Invalid option. Please try again."
            read -p "Press Enter to continue..."
            ;;
    esac
done
