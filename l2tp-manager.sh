#!/bin/bash

# L2TP Server Manager Script
# Auto Install & Configuration with Interactive Management
# Created for Ubuntu/Debian systems
#
# GitHub: https://github.com/safrinnetwork/
# Made by Mostech

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

# Source configuration
if [[ -f "$SCRIPT_DIR/config/defaults.conf" ]]; then
    source "$SCRIPT_DIR/config/defaults.conf"
else
    echo "Error: Configuration file not found!"
    exit 1
fi

# Source all library files
for lib_file in "$SCRIPT_DIR"/lib/*.sh; do
    if [[ -f "$lib_file" ]]; then
        source "$lib_file"
    else
        echo "Error: Library file $(basename "$lib_file") not found!"
        exit 1
    fi
done

# Check root
check_root

# Update PUBLIC_IP and DEFAULT_INTERFACE if needed
if [[ "$PUBLIC_IP" == "Unable to detect" ]]; then
    PUBLIC_IP=$(get_public_ip)
fi

if [[ -z "$DEFAULT_INTERFACE" ]]; then
    DEFAULT_INTERFACE=$(get_default_interface)

    if [[ -z "$DEFAULT_INTERFACE" ]]; then
        error "Cannot determine default network interface."
        exit 1
    fi
fi

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
    "--help"|"-h")
        echo "L2TP VPN Server Manager - Made by Mostech"
        echo "GitHub: https://github.com/safrinnetwork/"
        echo ""
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  start-forwards    Start port forwarding service"
        echo "  stop-forwards     Stop port forwarding service"
        echo "  --help, -h        Show this help message"
        echo ""
        echo "Run without arguments for interactive menu"
        exit 0
        ;;
esac

# Enable iptables persistence if available
if systemctl is-enabled netfilter-persistent >/dev/null 2>&1; then
    systemctl enable netfilter-persistent 2>/dev/null
fi

# Main loop
while true; do
    show_menu
    echo -e "${YELLOW}✨ Enter your choice (0-14): ${NC}"
    echo -ne "${GREEN}▶ ${NC}"
    read choice

    case $choice in
        1)
            show_installation_status
            install_status=$?

            if [[ $install_status -eq 0 ]]; then
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read
            elif [[ $install_status -eq 3 ]]; then
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
            uninstall_server
            read -p "Press Enter to continue..."
            ;;
        4)
            add_user
            read -p "Press Enter to continue..."
            ;;
        5)
            delete_user
            read -p "Press Enter to continue..."
            ;;
        6)
            edit_user
            read -p "Press Enter to continue..."
            ;;
        7)
            list_users
            read -p "Press Enter to continue..."
            ;;
        8)
            add_forward
            read -p "Press Enter to continue..."
            ;;
        9)
            delete_forward
            read -p "Press Enter to continue..."
            ;;
        10)
            list_forwards
            read -p "Press Enter to continue..."
            ;;
        11)
            log "Restarting port forwards..."
            stop_forwards
            sleep 2
            start_forwards
            log "Port forwards restarted"
            read -p "Press Enter to continue..."
            ;;
        12)
            log "Starting services..."
            systemctl start xl2tpd
            systemctl start l2tp-forwards
            log "Services started"
            read -p "Press Enter to continue..."
            ;;
        13)
            log "Stopping services..."
            systemctl stop xl2tpd
            systemctl stop l2tp-forwards
            stop_forwards
            log "Services stopped"
            read -p "Press Enter to continue..."
            ;;
        14)
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
            sleep 2
            ;;
    esac
done
