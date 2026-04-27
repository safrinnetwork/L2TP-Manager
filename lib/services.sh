#!/bin/bash
# Services Library
# Made by Mostech
# GitHub: https://github.com/safrinnetwork/

start_forwards() {
    log "Starting port forwards..."

    # Kill existing socat processes
    pkill -f "socat.*TCP4-LISTEN" 2>/dev/null
    sleep 1

    # Restore saved firewall rules if available
    firewall_restore_rules || warning "Could not restore saved firewall rules"

    # Setup static routes for L2TP networks
    if [[ -f /etc/l2tp-routes.conf ]]; then
        log "Setting up L2TP static routes..."
        while IFS=':' read -r network gateway desc; do
            # Skip comments and empty lines
            is_comment_or_empty "$network" && continue

            # Remove existing route if present (to avoid duplicate errors)
            ip route del "$network" 2>/dev/null

            # Add static route
            if ip route add "$network" via "$gateway" 2>/dev/null; then
                log "Added route: $network via $gateway ($desc)"
            else
                warning "Failed to add route: $network via $gateway"
            fi
        done < /etc/l2tp-routes.conf
    fi

    while IFS=':' read -r name ext_port int_ip int_port desc; do
        # Skip comments and empty lines
        is_comment_or_empty "$name" && continue

        # Ensure firewall rule exists for this port
        if ! firewall_check_rule -C INPUT -p tcp --dport "$ext_port" -j ACCEPT; then
            if firewall_add_rule -A INPUT -p tcp --dport "$ext_port" -j ACCEPT; then
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
    firewall_save_rules || warning "Could not save firewall rules"
}

stop_forwards() {
    log "Stopping port forwards..."
    pkill -f "socat.*TCP4-LISTEN" 2>/dev/null
}
