# L2TP Server Manager

Script interaktif untuk instalasi dan manajemen L2TP server di Ubuntu VPS. Dirancang untuk memberikan akses tunnel yang aman ke router MikroTik tanpa IP publik melalui port forwarding.

## Panduan Video

https://youtu.be/x9Py3JSm-aI

## Fitur Utama

- Instalasi otomatis L2TP server (tanpa IPsec)
- Manajemen user L2TP (tambah/hapus/edit)
- Port forwarding untuk akses service internal
- Monitoring status server real-time
- Integrasi systemd untuk service otomatis

## Cara Penggunaan

1. **Download dan jalankan script:**
   ```bash
   git clone https://github.com/safrinnetwork/L2TP-Manager/
   cd L2TP-Manager
   chmod +x l2tp-manager.sh
   sudo ./l2tp-manager.sh
   ```

2. **Pilih opsi 1** untuk instalasi L2TP server

3. **Pilih opsi 3** untuk menambah user L2TP

4. **Pilih opsi 7** untuk konfigurasi port forwarding

## Konfigurasi Jaringan

### Range IP VPN
- **Server IP**: 172.16.101.1
- **Client Range**: 172.16.101.10 - 172.16.101.100
- **DNS Servers**: 8.8.8.8, 8.8.4.4

### Port yang Digunakan
- **UDP 1701**: L2TP tunnel
- **Port custom**: Sesuai konfigurasi port forwarding

## Konfigurasi MikroTik Client

Untuk menghubungkan router MikroTik ke VPS:

```
/interface l2tp-client
add connect-to=IP_VPS_ANDA name=l2tp-out1 user=USERNAME password=PASSWORD
```

## Contoh Port Forwarding

Untuk akses Winbox MikroTik melalui VPS:
1. Tambah port forward: `IP_VPS:6000 -> 172.16.101.10:8291`
2. Akses Winbox via: `IP_VPS:6000`

## File Konfigurasi

Script ini mengelola file-file berikut:
- `/etc/xl2tpd/xl2tpd.conf` - Konfigurasi L2TP server
- `/etc/ppp/options.xl2tpd` - Opsi PPP untuk L2TP
- `/etc/ppp/chap-secrets` - Database autentikasi user
- `/etc/l2tp-forwards.conf` - Konfigurasi port forwarding
- `/etc/systemd/system/l2tp-forwards.service` - Service port forwarding

## Troubleshooting

### Masalah Koneksi
```bash
systemctl status xl2tpd              # Cek status service
journalctl -u xl2tpd -f              # Lihat log real-time
iptables -L -n                       # Verifikasi firewall
```

### Masalah Port Forward
```bash
systemctl status l2tp-forwards.service   # Cek status service forwarding
ps aux | grep socat                      # Cek proses socat
ss -tuln | grep PORT                     # Cek port listening
```

### Masalah IP Conflict
Jika terjadi konflik IP dengan jaringan lokal (misalnya dengan DHCP server router), script ini menggunakan range `172.16.101.0/24` yang tidak konflik dengan range umum seperti `10.x.x.x` atau `192.168.x.x`.

## Keamanan

- Menggunakan autentikasi CHAP (lebih aman dari PAP)
- Tanpa IPsec PSK (lebih sederhana)
- Firewall dikonfigurasi otomatis
- Validasi input untuk mencegah injection attack

## Persyaratan Sistem

- Ubuntu 18.04+ dengan IP publik
- Akses root atau sudo
- Koneksi internet stabil
- Port UDP 1701 terbuka

## Support

Untuk bantuan lebih lanjut:
- Cek log service: `journalctl -u xl2tpd`
- Status koneksi: Menu opsi 2