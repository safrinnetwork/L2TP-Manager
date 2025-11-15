#!/bin/bash
# Install Library
# Made by Mostech
# GitHub: https://github.com/safrinnetwork/

install_packages() {
    log "Installing required packages..."
    echo

    # Update package list with visible output
    echo -e "${CYAN}[1/2]${NC} Updating package list..."
    if ! apt update; then
        error "Failed to update package list"
        return 1
    fi
    echo -e "${GREEN}✓${NC} Package list updated\n"

    # Install packages with visible output
    echo -e "${CYAN}[2/2]${NC} Installing packages: xl2tpd ppp socat iptables-persistent curl..."
    local packages="xl2tpd ppp socat iptables-persistent curl"

    # Set DEBIAN_FRONTEND to prevent interactive prompts
    if ! DEBIAN_FRONTEND=noninteractive apt install -y $packages; then
        error "Package installation failed. Please check your internet connection and try again."
        return 1
    fi

    echo -e "${GREEN}✓${NC} All packages installed successfully\n"
    log "Packages installed successfully"
    return 0
}

configure_l2tp() {
    log "Configuring L2TP server..."

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
ip range = 172.16.101.10-172.16.101.100
local ip = 172.16.101.1
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

configure_firewall() {
    log "Configuring firewall and IP forwarding..."
    echo

    # Enable IP forwarding
    echo -e "${CYAN}[1/4]${NC} Enabling IP forwarding..."
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    fi

    if ! sysctl -p >/dev/null 2>&1; then
        error "Failed to apply sysctl settings"
        return 1
    fi
    echo -e "${GREEN}✓${NC} IP forwarding enabled\n"

    # Configure iptables with detected interface
    echo -e "${CYAN}[2/4]${NC} Configuring iptables rules..."
    local rules=(
        "iptables -t nat -A POSTROUTING -s 172.16.101.0/24 -o $DEFAULT_INTERFACE -j MASQUERADE"
        "iptables -A FORWARD -s 172.16.101.0/24 -j ACCEPT"
        "iptables -A FORWARD -d 172.16.101.0/24 -j ACCEPT"
        "iptables -A INPUT -p udp --dport 1701 -j ACCEPT"
    )

    for rule in "${rules[@]}"; do
        if ! eval "$rule" 2>/dev/null; then
            error "Failed to apply iptables rule: $rule"
            return 1
        fi
    done
    echo -e "${GREEN}✓${NC} Iptables rules configured (interface: $DEFAULT_INTERFACE)\n"

    # Save iptables rules
    echo -e "${CYAN}[3/4]${NC} Creating iptables directory..."
    mkdir -p /etc/iptables 2>/dev/null
    echo -e "${GREEN}✓${NC} Directory created\n"

    echo -e "${CYAN}[4/4]${NC} Saving iptables rules..."
    if ! iptables-save > /etc/iptables/rules.v4 2>/dev/null; then
        error "Failed to save iptables rules"
        return 1
    fi
    echo -e "${GREEN}✓${NC} Iptables rules saved\n"

    log "Firewall configured successfully (using interface: $DEFAULT_INTERFACE)"
    return 0
}

start_services() {
    log "Starting L2TP services..."
    echo

    echo -e "${CYAN}[1/3]${NC} Enabling xl2tpd service..."
    if ! systemctl enable xl2tpd >/dev/null 2>&1; then
        error "Failed to enable xl2tpd service"
        return 1
    fi
    echo -e "${GREEN}✓${NC} Service enabled\n"

    # Try to start service
    echo -e "${CYAN}[2/3]${NC} Starting xl2tpd service..."
    if ! systemctl start xl2tpd 2>/dev/null; then
        warning "Initial xl2tpd start failed, attempting automatic fix..."

        # Check for binding issues in logs
        if journalctl -u xl2tpd --no-pager -l 2>/dev/null | grep -q "Unable to bind socket"; then
            info "Detected socket binding issue, applying fix..."

            # Apply configuration fix
            fix_xl2tpd_config

            # Try starting again
            if systemctl start xl2tpd 2>/dev/null; then
                info "xl2tpd started successfully after configuration fix"
            else
                error "xl2tpd still failed to start after fix attempt"
                warning "Please check configuration manually"
                echo -e "\n${YELLOW}Service logs:${NC}"
                journalctl -u xl2tpd --no-pager -n 20
                return 1
            fi
        else
            error "xl2tpd failed to start for unknown reason"
            echo -e "\n${YELLOW}Service logs:${NC}"
            journalctl -u xl2tpd --no-pager -n 20
            return 1
        fi
    fi
    echo -e "${GREEN}✓${NC} Service started\n"

    # Wait a moment and verify service is running
    echo -e "${CYAN}[3/3]${NC} Verifying service status..."
    sleep 2
    if systemctl is-active --quiet xl2tpd; then
        echo -e "${GREEN}✓${NC} Service is running properly\n"
        log "L2TP service started successfully"
        return 0
    else
        error "L2TP service failed to start properly"
        echo -e "\n${YELLOW}Service status:${NC}"
        systemctl status xl2tpd --no-pager
        return 1
    fi
}

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

uninstall_server() {
    echo -e "\n${RED}⚠️  WARNING: L2TP Server Uninstallation${NC}"
    echo -e "${RED}===============================================${NC}\n"
    echo -e "${YELLOW}This will completely remove:${NC}"
    echo -e "   • All L2TP services"
    echo -e "   • All user configurations"
    echo -e "   • All port forwarding rules"
    echo -e "   • All firewall rules related to L2TP"
    echo -e "   • Service files and configurations"
    echo
    echo -e "${RED}⚠️  This action CANNOT be undone!${NC}\n"

    echo -ne "${YELLOW}Type \"UNINSTALL\" to confirm: ${NC}"
    read confirm

    if [[ "$confirm" != "UNINSTALL" ]]; then
        warning "Uninstallation cancelled."
        return 1
    fi

    echo
    echo -ne "${YELLOW}Do you also want to remove installed packages? (xl2tpd, ppp, socat) [y/N]: ${NC}"
    read remove_packages

    echo -e "\n${YELLOW}Starting uninstallation process...${NC}\n"

    # Stop all services
    echo -e "${CYAN}[1/8]${NC} Stopping services..."
    systemctl stop l2tp-forwards 2>/dev/null
    systemctl stop xl2tpd 2>/dev/null
    pkill -f "socat.*TCP4-LISTEN" 2>/dev/null
    sleep 2
    echo -e "${GREEN}✓${NC} Services stopped"

    # Disable services
    echo -e "${CYAN}[2/8]${NC} Disabling services..."
    systemctl disable l2tp-forwards 2>/dev/null
    systemctl disable xl2tpd 2>/dev/null
    echo -e "${GREEN}✓${NC} Services disabled"

    # Remove service files
    echo -e "${CYAN}[3/8]${NC} Removing service files..."
    rm -f /etc/systemd/system/l2tp-forwards.service
    systemctl daemon-reload
    echo -e "${GREEN}✓${NC} Service files removed"

    # Remove configuration files
    echo -e "${CYAN}[4/8]${NC} Removing configuration files..."
    rm -f /etc/ppp/chap-secrets.backup* 2>/dev/null
    rm -f /etc/xl2tpd/xl2tpd.conf.backup* 2>/dev/null
    rm -f /etc/ipsec.conf.backup* 2>/dev/null
    rm -f /etc/ipsec.secrets.backup* 2>/dev/null
    rm -f /etc/l2tp-forwards.conf 2>/dev/null
    rm -f /etc/ppp/options.xl2tpd 2>/dev/null

    # Restore original configs or remove L2TP configs
    if [[ -f /etc/xl2tpd/xl2tpd.conf ]]; then
        echo "" > /etc/xl2tpd/xl2tpd.conf
    fi
    if [[ -f /etc/ppp/chap-secrets ]]; then
        echo "# Secrets for authentication using CHAP" > /etc/ppp/chap-secrets
        echo "# client	server	secret			IP addresses" >> /etc/ppp/chap-secrets
    fi
    echo -e "${GREEN}✓${NC} Configuration files cleaned"

    # Remove iptables rules
    echo -e "${CYAN}[5/8]${NC} Removing firewall rules..."

    # Remove L2TP INPUT rules
    iptables -D INPUT -p udp --dport 1701 -j ACCEPT 2>/dev/null

    # Remove L2TP FORWARD rules (only for our subnet)
    iptables -D FORWARD -s 10.50.0.0/24 -j ACCEPT 2>/dev/null
    iptables -D FORWARD -d 10.50.0.0/24 -j ACCEPT 2>/dev/null

    # Remove NAT rules for L2TP
    iptables -t nat -D POSTROUTING -s 10.50.0.0/24 -o "$DEFAULT_INTERFACE" -j MASQUERADE 2>/dev/null

    # Remove port forward rules from config file
    if [[ -f /etc/l2tp-forwards.conf ]]; then
        while IFS=':' read -r name ext_port int_ip int_port desc; do
            [[ $name =~ ^#.*$ ]] || [[ -z $name ]] && continue
            iptables -D INPUT -p tcp --dport "$ext_port" -j ACCEPT 2>/dev/null
            iptables -t nat -D PREROUTING -p tcp --dport "$ext_port" -j DNAT --to-destination "$int_ip:$int_port" 2>/dev/null
        done < /etc/l2tp-forwards.conf
    fi

    # Save iptables
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    fi

    echo -e "${GREEN}✓${NC} Firewall rules removed"

    # Disable IP forwarding
    echo -e "${CYAN}[6/8]${NC} Disabling IP forwarding..."
    sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1
    echo -e "${GREEN}✓${NC} IP forwarding disabled"

    # Remove packages if requested
    if [[ $remove_packages =~ ^[yY]$ ]]; then
        echo -e "${CYAN}[7/9]${NC} Removing packages..."
        apt-get remove --purge -y xl2tpd ppp socat >/dev/null 2>&1
        apt-get autoremove -y >/dev/null 2>&1
        echo -e "${GREEN}✓${NC} Packages removed (xl2tpd, ppp, socat)"
    else
        echo -e "${CYAN}[7/9]${NC} Skipping package removal (packages kept)"
    fi

    # Clean up logs and temporary files
    echo -e "${CYAN}[8/9]${NC} Cleaning up logs and temporary files..."
    rm -f /var/log/l2tp-*.log 2>/dev/null
    journalctl --vacuum-time=1s --unit=xl2tpd >/dev/null 2>&1
    journalctl --vacuum-time=1s --unit=l2tp-forwards >/dev/null 2>&1

    # Remove iptables directory if empty
    if [[ -d /etc/iptables ]]; then
        rmdir /etc/iptables 2>/dev/null || true
    fi
    echo -e "${GREEN}✓${NC} Logs and temporary files cleaned"

    # Final cleanup and verification
    echo -e "${CYAN}[9/9]${NC} Final verification..."

    # Kill any remaining ppp processes
    pkill -9 pppd 2>/dev/null || true

    # Remove any remaining ppp interfaces
    for iface in $(ip link show | grep "ppp" | cut -d: -f2 | tr -d ' '); do
        ip link delete "$iface" 2>/dev/null || true
    done

    echo -e "${GREEN}✓${NC} Final cleanup completed"

    echo
    echo -e "${GREEN}✅ L2TP Server successfully uninstalled!${NC}\n"
    echo -e "${CYAN}===============================================${NC}"
    echo -e "${YELLOW}📋 Uninstallation Summary:${NC}"
    echo -e "   • Services: ${GREEN}✓ Stopped and disabled${NC}"
    echo -e "     - xl2tpd service"
    echo -e "     - l2tp-forwards service"
    echo -e "   • Configuration files: ${GREEN}✓ Removed${NC}"
    echo -e "     - /etc/xl2tpd/xl2tpd.conf"
    echo -e "     - /etc/ppp/options.xl2tpd"
    echo -e "     - /etc/ppp/chap-secrets (reset)"
    echo -e "     - /etc/l2tp-forwards.conf"
    echo -e "     - All backup files"
    echo -e "   • Firewall rules: ${GREEN}✓ Removed${NC}"
    echo -e "     - L2TP port (1701)"
    echo -e "     - NAT rules for 10.50.0.0/24"
    echo -e "     - FORWARD rules"
    echo -e "     - Port forwarding rules"
    echo -e "   • IP forwarding: ${GREEN}✓ Disabled${NC}"
    echo -e "   • System files: ${GREEN}✓ Cleaned${NC}"
    if [[ $remove_packages =~ ^[yY]$ ]]; then
        echo -e "   • Packages: ${GREEN}✓ Uninstalled (xl2tpd, ppp, socat)${NC}"
    else
        echo -e "   • Packages: ${YELLOW}⚠ Kept on system (xl2tpd, ppp, socat)${NC}"
        echo -e "     ${CYAN}Run 'apt remove --purge xl2tpd ppp socat' to remove manually${NC}"
    fi
    echo -e "${CYAN}===============================================${NC}\n"
    echo -e "${GREEN}Your system has been cleaned from L2TP VPN Server.${NC}\n"

    log "L2TP server uninstalled successfully"
}

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

init_forwards_config() {
    if [ ! -f "$FORWARDS_CONFIG" ]; then
        cat > "$FORWARDS_CONFIG" << EOF
# L2TP Port Forwards Configuration
# Format: name:external_port:internal_ip:internal_port:description
# Example: winbox:8889:10.50.0.10:8291:MikroTik Winbox Access
EOF
    fi
}

