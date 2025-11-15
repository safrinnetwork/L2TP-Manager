#!/bin/bash
# Core Utilities Library
# Made by Mostech
# GitHub: https://github.com/safrinnetwork/

# Logging functions
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

# Execute command with error checking
exec_cmd() {
    local cmd="$1"
    local error_msg="$2"

    if ! eval "$cmd" >/dev/null 2>&1; then
        [[ -n "$error_msg" ]] && error "$error_msg"
        return 1
    fi
    return 0
}

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

# Get public IP
get_public_ip() {
    local ip=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null)
    if [[ -z "$ip" ]]; then
        ip=$(curl -s -4 --max-time 5 icanhazip.com 2>/dev/null)
    fi
    if [[ -z "$ip" ]]; then
        ip=$(curl -s -4 --max-time 5 ipinfo.io/ip 2>/dev/null)
    fi
    if [[ -z "$ip" ]]; then
        ip="Unable to detect"
    fi
    echo "$ip"
}

# Get default network interface
get_default_interface() {
    local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$interface" ]]; then
        interface=$(ip link show | grep -E "^[0-9]+: (eth|ens|enp)" | head -n1 | cut -d: -f2 | tr -d ' ')
    fi
    echo "$interface"
}

# Get system information
get_system_info() {
    local os_info=""
    local cpu_info=""
    local ram_info=""
    local disk_info=""

    # OS Info
    if [ -f /etc/os-release ]; then
        os_info=$(grep "PRETTY_NAME" /etc/os-release | cut -d'"' -f2)
    else
        os_info="Unknown"
    fi

    # CPU Info
    if command -v lscpu >/dev/null 2>&1; then
        local cpu_model=$(lscpu | grep "Model name" | cut -d':' -f2 | xargs)
        local cpu_cores=$(lscpu | grep "^CPU(s):" | awk '{print $2}')
        cpu_info="$cpu_model ($cpu_cores cores)"
    else
        cpu_info="Unknown"
    fi

    # RAM Info
    if command -v free >/dev/null 2>&1; then
        ram_info=$(free -h | awk '/^Mem:/ {printf "%s / %s (%.1f%% used)", $3, $2, ($3/$2)*100}')
    else
        ram_info="Unknown"
    fi

    # Disk Info
    if command -v df >/dev/null 2>&1; then
        disk_info=$(df -h / | awk 'NR==2 {printf "%s / %s (%s used)", $3, $2, $5}')
    else
        disk_info="Unknown"
    fi

    echo "OS:$os_info"
    echo "CPU:$cpu_info"
    echo "RAM:$ram_info"
    echo "Storage:$disk_info"
}

# Check if username already exists
username_exists() {
    local username="$1"
    grep -q "^$username\s" "$CHAP_SECRETS" 2>/dev/null
}

# Check if IP is already assigned
ip_already_assigned() {
    local ip="$1"
    grep -q "\s${ip}$" "$CHAP_SECRETS" 2>/dev/null
}

# Get next available IP address
get_next_available_ip() {
    local base_ip="172.16.101"
    local start_range=10
    local end_range=100

    # Get all currently assigned IPs
    local assigned_ips=()
    while IFS= read -r line; do
        [[ $line =~ ^#.*$ ]] || [[ -z $line ]] && continue
        local ip=$(echo "$line" | awk '{print $4}')
        [[ -n "$ip" ]] && assigned_ips+=("$ip")
    done < "$CHAP_SECRETS"

    # Find first available IP
    for i in $(seq $start_range $end_range); do
        local test_ip="${base_ip}.${i}"
        local is_assigned=0

        for assigned_ip in "${assigned_ips[@]}"; do
            if [[ "$assigned_ip" == "$test_ip" ]]; then
                is_assigned=1
                break
            fi
        done

        if [[ $is_assigned -eq 0 ]]; then
            echo "$test_ip"
            return 0
        fi
    done

    return 1
}

# Generate random port (range 1000-9999)
generate_random_port() {
    echo $((RANDOM % 9000 + 1000))
}

# Check if port is in use
port_in_use() {
    local port="$1"

    # Check if port is used in system
    if ss -tuln | grep -q ":${port}\s"; then
        return 0
    fi

    # Check if port is in forwards config
    if grep -q ":${port}:" "$FORWARDS_CONFIG" 2>/dev/null; then
        return 0
    fi

    return 1
}

# Generate unique port
generate_unique_port() {
    local max_attempts=100
    local attempt=0

    while (( attempt < max_attempts )); do
        local port=$(generate_random_port)
        if ! port_in_use "$port"; then
            echo "$port"
            return 0
        fi
        ((attempt++))
    done

    return 1
}
