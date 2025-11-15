#!/bin/bash
# Forwards Library
# Made by Mostech
# GitHub: https://github.com/safrinnetwork/

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
            systemctl restart l2tp-forwards >/dev/null 2>&1
            info "Port forwarding service restarted"
        fi
    else
        error "No forwards were deleted"
    fi
}

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

