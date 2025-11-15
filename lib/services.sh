#!/bin/bash
# Services Library
# Made by Mostech
# GitHub: https://github.com/safrinnetwork/

start_forwards() {
    log "Starting port forwards..."

    # Kill existing socat processes
    pkill -f "socat.*TCP4-LISTEN" 2>/dev/null
    sleep 1

    # Restore saved iptables rules if available
    if [[ -f /etc/iptables/rules.v4 ]]; then
        if command -v iptables-restore >/dev/null 2>&1; then
            iptables-restore < /etc/iptables/rules.v4 2>/dev/null || warning "Could not restore saved iptables rules"
        fi
    fi

    # Setup static routes for L2TP networks
    if [[ -f /etc/l2tp-routes.conf ]]; then
        log "Setting up L2TP static routes..."
        while IFS=':' read -r network gateway desc; do
            # Skip comments and empty lines
            [[ $network =~ ^#.*$ ]] || [[ -z $network ]] && continue

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

stop_forwards() {
    log "Stopping port forwards..."
    pkill -f "socat.*TCP4-LISTEN" 2>/dev/null
}

