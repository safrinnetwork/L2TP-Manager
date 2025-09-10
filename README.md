# L2TP Server Manager

Interactive L2TP server installation and management script for Ubuntu VPS. Designed to provide secure tunnel access to MikroTik routers without public IP addresses through port forwarding.

## Overview

This project provides a complete solution for:
- Setting up L2TP server without IPsec on Ubuntu VPS
- Managing L2TP users (add/delete/edit)
- Port forwarding management for accessing internal services
- Automated service management

## Quick Start

1. **Download and run the script:**
   ```bash
   chmod +x l2tp-manager.sh
   ./l2tp-manager.sh
   ```

2. **Select option 1 to auto-install L2TP server**

3. **Add L2TP users using option 3**

4. **Configure port forwards using option 7**

## Features

### Main Functions
- **Auto Installation**: Automatically installs xl2tpd, ppp, socat, and configures firewall
- **Server Status**: Real-time monitoring of L2TP services and connections

### User Management
- **Add Users**: Create new L2TP users with custom credentials
- **Delete Users**: Remove existing users safely
- **Edit Users**: Modify user credentials and settings
- **List Users**: View all configured L2TP users

### Port Forward Management
- **Add Forwards**: Create port forwarding rules using socat
- **Delete Forwards**: Remove existing port forwards
- **List Forwards**: View active port forwarding rules
- **Restart Forwards**: Restart all forwarding services

### Service Management
- **Start/Stop/Restart**: Control xl2tpd and forwarding services
- **Systemd Integration**: Automatic service management and startup

## Configuration Files

The script manages these configuration files:

- `/etc/xl2tpd/xl2tpd.conf` - Main L2TP server configuration
- `/etc/ppp/options.xl2tpd` - PPP options for L2TP
- `/etc/ppp/chap-secrets` - User authentication database
- `/etc/systemd/system/winbox-forward.service` - Port forwarding service
- `/usr/local/bin/*.sh` - Port forwarding scripts

## Network Configuration

### Default IP Range
- **Server IP**: 10.50.0.1
- **Client Range**: 10.50.0.2 - 10.50.0.10
- **DNS Servers**: 8.8.8.8, 8.8.4.4

### Firewall Rules
The script automatically configures:
- UDP port 1701 (L2TP)
- Custom port forwarding rules
- NAT and masquerading for VPN traffic

## MikroTik Client Configuration

To connect your MikroTik router:

```
/interface l2tp-client
add connect-to=YOUR_VPS_IP name=l2tp-out1 user=USERNAME password=PASSWORD
```

## Port Forwarding Example

To access MikroTik Winbox through VPS:
1. Add port forward: `VPS_IP:8889 -> 10.50.0.2:8291`
2. Access Winbox via: `http://VPS_IP:8889`

## Troubleshooting

### Connection Issues
- Check L2TP service: `systemctl status xl2tpd`
- View logs: `journalctl -u xl2tpd -f`
- Verify firewall: `iptables -L -n`

### Port Forward Issues
- Check socat processes: `ps aux | grep socat`
- Verify service status: `systemctl status winbox-forward`
- Test connectivity: `telnet VPS_IP PORT`

## Security Notes

- Uses CHAP authentication (more secure than PAP)
- No IPsec PSK required
- Firewall rules automatically configured
- Services run with appropriate permissions

## Requirements

- Ubuntu 18.04+ VPS with public IP
- Root or sudo access
- Internet connectivity
- Open UDP port 1701

## Support

For issues or questions, check:
- Service logs: `journalctl -u xl2tpd`
- Connection status in script menu option 2
- Network connectivity with `ping` and `telnet`