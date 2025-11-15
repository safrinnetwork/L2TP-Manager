#!/bin/bash
# Menu Library
# Made by Mostech
# GitHub: https://github.com/safrinnetwork/

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

show_menu() {
    clear

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
    echo -e "   ${GREEN}[3]${NC}  🗑️  Uninstall L2TP Server"
    echo
    echo -e "${CYAN}👥 USER MANAGEMENT${NC}"
    echo -e "   ${GREEN}[4]${NC}  ➕ Add New L2TP User"
    echo -e "   ${GREEN}[5]${NC}  ❌ Delete L2TP User"
    echo -e "   ${GREEN}[6]${NC}  ✏️  Edit L2TP User"
    echo -e "   ${GREEN}[7]${NC}  📋 List All L2TP Users"
    echo
    echo -e "${CYAN}🔀 PORT FORWARDING${NC}"
    echo -e "   ${GREEN}[8]${NC}  ➕ Add Port Forward Rule"
    echo -e "   ${GREEN}[9]${NC}  ❌ Delete Port Forward"
    echo -e "   ${GREEN}[10]${NC} 📋 List Active Forwards"
    echo -e "   ${GREEN}[11]${NC} 🔄 Restart All Forwards"
    echo
    echo -e "${CYAN}⚙️  SERVICE CONTROL${NC}"
    echo -e "   ${GREEN}[12]${NC} ✅ Start All Services"
    echo -e "   ${GREEN}[13]${NC} ⏹️  Stop All Services"
    echo -e "   ${GREEN}[14]${NC} 🔄 Restart All Services"
    echo
    echo -e "   ${RED}[0]${NC}  🚪 Exit Program"
    echo
    echo -e "${CYAN}===============================================================${NC}"
    echo -e "${YELLOW}💡 Tip: Use Ctrl+C to cancel any operation${NC}"
    echo -e "${PURPLE}🔗 GitHub: https://github.com/safrinnetwork/${NC}"
    echo
}

