#!/bin/bash

# L2TP Static Routes Manager
# Management script for L2TP VPN static routes
# Created for Ubuntu/Debian systems
#
# GitHub: https://github.com/safrinnetwork/
# Made by Mostech

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export NC='\033[0m' # No Color

# Configuration paths
ROUTES_CONFIG="/etc/l2tp-routes.conf"
CHAP_SECRETS="/etc/ppp/chap-secrets"

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

# Validate IP network CIDR
validate_network() {
    local network="$1"
    if [[ $network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0
    fi
    return 1
}

# Validate IP address
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

# Sanitize input
sanitize_input() {
    local input="$1"
    echo "$input" | sed 's/[;&|`$(){}\\<>]//g'
}

# Get L2TP clients and their IPs
get_l2tp_clients() {
    echo -e "${YELLOW}Available L2TP Clients:${NC}"
    echo -e "${CYAN}---------------------------------------${NC}"
    local count=0
    while IFS= read -r line; do
        [[ $line =~ ^#.*$ ]] || [[ -z $line ]] && continue
        local username=$(echo "$line" | awk '{print $1}')
        local ip=$(echo "$line" | awk '{print $4}')
        ((count++))
        printf "%2d. %-20s IP: %s\n" "$count" "$username" "$ip"
    done < "$CHAP_SECRETS"

    if [[ $count -eq 0 ]]; then
        echo -e "   ${YELLOW}No L2TP clients configured${NC}"
    fi
    echo -e "${CYAN}---------------------------------------${NC}"
}

# Add new static route
add_route() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}            Add Static Route               ${NC}"
    echo -e "${BLUE}            Made by Mostech               ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"

    # Show available L2TP clients
    get_l2tp_clients
    echo

    local network gateway description

    # Network validation
    while true; do
        read -p "Enter destination network (CIDR format, e.g., 10.50.0.0/24): " network
        network=$(sanitize_input "$network")

        if [[ -z "$network" ]]; then
            error "Network cannot be empty"
            continue
        fi

        if ! validate_network "$network"; then
            error "Invalid network format. Use CIDR notation (e.g., 10.50.0.0/24)"
            continue
        fi

        # Check if route already exists
        if grep -q "^$network:" "$ROUTES_CONFIG" 2>/dev/null; then
            error "Route for network '$network' already exists!"
            continue
        fi
        break
    done

    # Gateway IP validation
    while true; do
        read -p "Enter gateway IP (L2TP client IP): " gateway
        gateway=$(sanitize_input "$gateway")

        if [[ -z "$gateway" ]]; then
            error "Gateway IP cannot be empty"
            continue
        fi

        if ! validate_ip "$gateway"; then
            error "Invalid IP address format"
            continue
        fi

        # Check if gateway is a known L2TP client
        if ! grep -q "\s${gateway}$" "$CHAP_SECRETS" 2>/dev/null; then
            warning "Gateway IP '$gateway' is not in L2TP clients list"
            read -p "Continue anyway? (y/N): " confirm
            if [[ ! $confirm =~ ^[yY]$ ]]; then
                continue
            fi
        fi
        break
    done

    # Description
    read -p "Enter description (optional): " description
    description=$(sanitize_input "$description")
    [[ -z "$description" ]] && description="Static route to $network"

    # Add route to config
    local config_line="$network:$gateway:$description"
    if echo "$config_line" >> "$ROUTES_CONFIG"; then
        log "Route added to configuration: $network via $gateway"
    else
        error "Failed to add route to configuration file"
        return 1
    fi

    # Ask if want to apply immediately
    read -p "Apply route immediately? (Y/n): " apply_now
    if [[ -z "$apply_now" ]] || [[ $apply_now =~ ^[yY]$ ]]; then
        # Check if gateway is reachable
        if ip route add "$network" via "$gateway" 2>/dev/null; then
            log "Route applied successfully: $network via $gateway"
            info "Route is now active"
        else
            warning "Failed to apply route. Gateway may not be reachable yet."
            info "Route will be applied when L2TP forwards service starts"
        fi
    else
        info "Route saved to config. It will be applied on next service restart."
    fi

    echo -e "\n${GREEN}✓ Route added successfully!${NC}"
}

# Delete static route
delete_route() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}           Delete Static Route             ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"

    # Get all routes
    local routes_list=$(grep -v "^#" "$ROUTES_CONFIG" 2>/dev/null | grep -v "^$")
    if [[ -z "$routes_list" ]]; then
        warning "No static routes found!"
        return 1
    fi

    # Display numbered list
    echo -e "${YELLOW}Current static routes:${NC}"
    local counter=1
    while IFS=':' read -r network gateway desc; do
        [[ -z "$network" ]] && continue
        printf "%2d. %-20s via %-15s (%s)\n" "$counter" "$network" "$gateway" "$desc"
        ((counter++))
    done <<< "$routes_list"

    echo -e "\n${CYAN}Options:${NC}"
    echo "1. Enter network(s) directly: 10.50.0.0/24,192.168.1.0/24"
    echo "2. Enter number(s): 1,2,3"
    echo "3. Enter 0 to cancel"

    read -p "Enter selection: " selection

    # Handle cancellation
    if [[ "$selection" == "0" ]]; then
        info "Deletion cancelled"
        return 0
    fi

    local routes_to_delete=()

    # Check if input contains only numbers and commas
    if [[ "$selection" =~ ^[0-9,]+$ ]]; then
        # Number-based selection
        IFS=',' read -ra numbers <<< "$selection"
        local total_routes=$(echo "$routes_list" | wc -l)

        for num in "${numbers[@]}"; do
            num=$(echo "$num" | xargs)
            if [[ "$num" -gt 0 && "$num" -le "$total_routes" ]]; then
                local route_line=$(echo "$routes_list" | sed -n "${num}p")
                local network=$(echo "$route_line" | cut -d':' -f1)
                routes_to_delete+=("$network")
            else
                warning "Invalid number: $num (valid range: 1-$total_routes)"
            fi
        done
    else
        # Network-based selection
        IFS=',' read -ra networks <<< "$selection"
        for network in "${networks[@]}"; do
            network=$(echo "$network" | xargs)
            if grep -q "^$network:" "$ROUTES_CONFIG"; then
                routes_to_delete+=("$network")
            else
                warning "Route for network '$network' not found!"
            fi
        done
    fi

    # Check if any valid routes to delete
    if [[ ${#routes_to_delete[@]} -eq 0 ]]; then
        error "No valid routes selected for deletion!"
        return 1
    fi

    # Show routes to be deleted
    echo -e "\n${YELLOW}Routes to be deleted:${NC}"
    for network in "${routes_to_delete[@]}"; do
        local route_info=$(grep "^$network:" "$ROUTES_CONFIG")
        local gateway=$(echo "$route_info" | cut -d':' -f2)
        local desc=$(echo "$route_info" | cut -d':' -f3)
        echo "• $network via $gateway ($desc)"
    done

    # Confirm deletion
    read -p "Are you sure you want to delete these ${#routes_to_delete[@]} route(s)? (y/N): " confirm
    if [[ $confirm != [yY] ]]; then
        info "Deletion cancelled"
        return 0
    fi

    # Delete routes
    local deleted_count=0
    for network in "${routes_to_delete[@]}"; do
        # Remove from active routing table
        if ip route del "$network" 2>/dev/null; then
            info "Removed active route: $network"
        fi

        # Delete from config
        if sed -i "/^$(echo "$network" | sed 's/\//\\\//g'):/d" "$ROUTES_CONFIG"; then
            log "Route '$network' deleted from configuration"
            ((deleted_count++))
        else
            error "Failed to delete route '$network' from configuration"
        fi
    done

    if [[ $deleted_count -gt 0 ]]; then
        echo -e "\n${GREEN}✓ Successfully deleted $deleted_count route(s)${NC}"
    else
        error "No routes were deleted"
    fi
}

# List all static routes
list_routes() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}          Static Routes List               ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"

    # Check if routes exist
    local routes_exist=false
    while read -r line; do
        [[ $line =~ ^#.*$ ]] || [[ -z $line ]] && continue
        routes_exist=true
        break
    done < "$ROUTES_CONFIG"

    if [[ "$routes_exist" != "true" ]]; then
        warning "No static routes configured!"
        return 1
    fi

    echo -e "${YELLOW}Configured Routes:${NC}"
    echo -e "${CYAN}---------------------------------------${NC}"

    local count=0
    while IFS=':' read -r network gateway desc; do
        [[ $network =~ ^#.*$ ]] || [[ -z $network ]] && continue

        ((count++))
        echo -e "${CYAN}[$count] Network: ${GREEN}$network${NC}"
        echo -e "    Gateway: ${GREEN}$gateway${NC}"
        echo -e "    Description: ${PURPLE}$desc${NC}"

        # Check if route is active
        if ip route show | grep -q "^$network via $gateway"; then
            echo -e "    Status: ${GREEN}✓ Active${NC}"
        else
            echo -e "    Status: ${YELLOW}○ Inactive${NC}"
        fi
        echo
    done < "$ROUTES_CONFIG"

    echo -e "${CYAN}===============================================${NC}"
    echo -e "${YELLOW}Total Routes: ${GREEN}$count${NC}"
    echo -e "${CYAN}===============================================${NC}"
}

# Test route connectivity
test_connectivity() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}         Test Route Connectivity           ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"

    # Get all routes
    local routes_list=$(grep -v "^#" "$ROUTES_CONFIG" 2>/dev/null | grep -v "^$")
    if [[ -z "$routes_list" ]]; then
        warning "No static routes configured!"
        return 1
    fi

    echo -e "${YELLOW}Select route to test:${NC}"
    local counter=1
    while IFS=':' read -r network gateway desc; do
        [[ -z "$network" ]] && continue
        printf "%2d. %-20s via %-15s\n" "$counter" "$network" "$gateway"
        ((counter++))
    done <<< "$routes_list"

    echo -e "\n${CYAN}Options:${NC}"
    echo "1. Enter route number"
    echo "2. Enter target IP directly"
    echo "3. Enter 0 to cancel"

    read -p "Enter selection: " selection

    if [[ "$selection" == "0" ]]; then
        return 0
    fi

    local target_ip=""

    # Check if input is a number (route selection)
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        local total_routes=$(echo "$routes_list" | wc -l)
        if [[ "$selection" -gt 0 && "$selection" -le "$total_routes" ]]; then
            local route_line=$(echo "$routes_list" | sed -n "${selection}p")
            local network=$(echo "$route_line" | cut -d':' -f1)

            # Extract network address from CIDR
            read -p "Enter target IP in network $network: " target_ip
            target_ip=$(sanitize_input "$target_ip")
        else
            error "Invalid selection"
            return 1
        fi
    else
        # Direct IP input
        target_ip=$(sanitize_input "$selection")
    fi

    # Validate IP
    if ! validate_ip "$target_ip"; then
        error "Invalid IP address: $target_ip"
        return 1
    fi

    # Perform ping test
    echo -e "\n${YELLOW}Testing connectivity to $target_ip...${NC}"
    echo -e "${CYAN}---------------------------------------${NC}"

    if ping -c 4 -W 2 "$target_ip"; then
        echo -e "${CYAN}---------------------------------------${NC}"
        echo -e "${GREEN}✓ Connectivity test PASSED${NC}"
    else
        echo -e "${CYAN}---------------------------------------${NC}"
        echo -e "${RED}✗ Connectivity test FAILED${NC}"

        # Show route for this IP
        echo -e "\n${YELLOW}Route information for $target_ip:${NC}"
        ip route get "$target_ip" 2>/dev/null || echo "No route found"
    fi
}

# Apply all routes from config
apply_routes() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}           Apply Static Routes             ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"

    local applied_count=0
    local failed_count=0

    while IFS=':' read -r network gateway desc; do
        [[ $network =~ ^#.*$ ]] || [[ -z $network ]] && continue

        # Remove existing route if present
        ip route del "$network" 2>/dev/null

        # Add route
        if ip route add "$network" via "$gateway" 2>/dev/null; then
            log "Applied route: $network via $gateway"
            ((applied_count++))
        else
            error "Failed to apply route: $network via $gateway"
            ((failed_count++))
        fi
    done < "$ROUTES_CONFIG"

    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${GREEN}✓ Routes applied: $applied_count${NC}"
    if [[ $failed_count -gt 0 ]]; then
        echo -e "${RED}✗ Routes failed: $failed_count${NC}"
    fi
    echo -e "${CYAN}===============================================${NC}"
}

# Show route status
show_status() {
    echo -e "\n${CYAN}===============================================${NC}"
    echo -e "${CYAN}          Static Routes Status             ${NC}"
    echo -e "${CYAN}===============================================${NC}\n"

    echo -e "${YELLOW}Configuration File:${NC} $ROUTES_CONFIG"

    local total_configured=$(grep -v "^#" "$ROUTES_CONFIG" 2>/dev/null | grep -v "^$" | wc -l)
    echo -e "${YELLOW}Total Configured:${NC} $total_configured route(s)"

    echo -e "\n${YELLOW}Active Routes:${NC}"
    echo -e "${CYAN}---------------------------------------${NC}"

    local active_count=0
    while IFS=':' read -r network gateway desc; do
        [[ $network =~ ^#.*$ ]] || [[ -z $network ]] && continue

        if ip route show | grep -q "^$network via $gateway"; then
            echo -e "${GREEN}✓${NC} $network via $gateway"
            ((active_count++))
        else
            echo -e "${YELLOW}○${NC} $network via $gateway ${RED}(inactive)${NC}"
        fi
    done < "$ROUTES_CONFIG"

    echo -e "${CYAN}---------------------------------------${NC}"
    echo -e "${YELLOW}Active Routes:${NC} $active_count / $total_configured"

    echo -e "\n${YELLOW}L2TP Forwards Service:${NC}"
    local service_status=$(systemctl is-active l2tp-forwards 2>/dev/null)
    if [[ "$service_status" == "active" ]]; then
        echo -e "   Status: ${GREEN}✓ Running${NC}"
    else
        echo -e "   Status: ${RED}✗ Not running${NC}"
    fi

    echo -e "\n${CYAN}===============================================${NC}"
}

# Show menu
show_menu() {
    clear

    echo -e "${CYAN}===============================================${NC}"
    echo -e "${CYAN}     🔀 L2TP Static Routes Manager 🔀      ${NC}"
    echo -e "${CYAN}         Professional Edition              ${NC}"
    echo -e "${BLUE}            Made by Mostech               ${NC}"
    echo -e "${CYAN}===============================================${NC}"
    echo

    echo -e "${CYAN}📊 ROUTE MANAGEMENT${NC}"
    echo -e "   ${GREEN}[1]${NC}  ➕ Add Static Route"
    echo -e "   ${GREEN}[2]${NC}  ❌ Delete Static Route"
    echo -e "   ${GREEN}[3]${NC}  📋 List All Routes"
    echo -e "   ${GREEN}[4]${NC}  📊 Show Routes Status"
    echo
    echo -e "${CYAN}🔧 OPERATIONS${NC}"
    echo -e "   ${GREEN}[5]${NC}  🔄 Apply All Routes"
    echo -e "   ${GREEN}[6]${NC}  🧪 Test Connectivity"
    echo -e "   ${GREEN}[7]${NC}  🔄 Restart L2TP Forwards Service"
    echo
    echo -e "   ${RED}[0]${NC}  🚪 Exit"
    echo
    echo -e "${CYAN}===============================================${NC}"
    echo -e "${YELLOW}💡 Routes are auto-applied on service restart${NC}"
    echo -e "${PURPLE}🔗 GitHub: https://github.com/safrinnetwork/${NC}"
    echo
}

# Check root
check_root

# Initialize config file if not exists
if [ ! -f "$ROUTES_CONFIG" ]; then
    cat > "$ROUTES_CONFIG" << 'EOF'
# L2TP Static Routes Configuration
# Format: network/cidr:l2tp_gateway_ip:description
# Example: 10.50.0.0/24:172.16.101.10:MikroTik Local Network
EOF
    log "Created new routes configuration file: $ROUTES_CONFIG"
fi

# Main loop
while true; do
    show_menu
    echo -e "${YELLOW}✨ Enter your choice (0-7): ${NC}"
    echo -ne "${GREEN}▶ ${NC}"
    read choice

    case $choice in
        1)
            add_route
            read -p "Press Enter to continue..."
            ;;
        2)
            delete_route
            read -p "Press Enter to continue..."
            ;;
        3)
            list_routes
            read -p "Press Enter to continue..."
            ;;
        4)
            show_status
            read -p "Press Enter to continue..."
            ;;
        5)
            apply_routes
            read -p "Press Enter to continue..."
            ;;
        6)
            test_connectivity
            read -p "Press Enter to continue..."
            ;;
        7)
            log "Restarting L2TP forwards service..."
            systemctl restart l2tp-forwards
            log "Service restarted"
            read -p "Press Enter to continue..."
            ;;
        0)
            clear
            echo -e "\n${CYAN}===============================================${NC}"
            echo -e "${CYAN}   🚀 Thank you for using Routes Manager!  ${NC}"
            echo -e "${CYAN}                                               ${NC}"
            echo -e "${CYAN}      💻 Professional VPN Solution          ${NC}"
            echo -e "${CYAN}        Stay connected, stay secure!        ${NC}"
            echo -e "${CYAN}                                               ${NC}"
            echo -e "${BLUE}            Made by Mostech                 ${NC}"
            echo -e "${CYAN}===============================================${NC}\n"
            exit 0
            ;;
        *)
            error "Invalid option. Please try again."
            sleep 2
            ;;
    esac
done
