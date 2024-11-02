# PowerShell Script to Configure Firewall Rules for Competition Topology

# Block All Inbound and Outbound Connections (Default Policy)
Invoke-Expression "netsh advfirewall reset"

New-NetFirewallRule -DisplayName "Block All Inbound" -Direction Inbound -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Block All Outbound" -Direction Outbound -Action Block -Enabled True

# Allow ICMP (Ping) Globally
New-NetFirewallRule -DisplayName "Allow ICMP" -Direction Inbound -Protocol ICMPv4 -Action Allow -Enabled True

# ============================
# Firewall Rules for Each Machine
# ============================

# 1. Windows 10 (WinRM) - 10.7.1.1
# Allow WinRM (HTTP) Port 5985
New-NetFirewallRule -DisplayName "Allow WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Enabled True

# 2. Windows 10 (ICMP) - 10.7.1.2
# Allow ICMP for ping (already allowed globally)

# 3. Windows Server 2022 (AD/DNS/LDAP) - 10.7.1.3
# Allow LDAP (TCP/UDP 389)
New-NetFirewallRule -DisplayName "Allow LDAP TCP" -Direction Inbound -Protocol TCP -LocalPort 389 -Action Allow -Enabled True
New-NetFirewallRule -DisplayName "Allow LDAP UDP" -Direction Inbound -Protocol UDP -LocalPort 389 -Action Allow -Enabled True

# Allow DNS (TCP/UDP 53)
New-NetFirewallRule -DisplayName "Allow DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Enabled True
New-NetFirewallRule -DisplayName "Allow DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Enabled True

# Allow Kerberos (TCP/UDP 88)
New-NetFirewallRule -DisplayName "Allow Kerberos TCP" -Direction Inbound -Protocol TCP -LocalPort 88 -Action Allow -Enabled True
New-NetFirewallRule -DisplayName "Allow Kerberos UDP" -Direction Inbound -Protocol UDP -LocalPort 88 -Action Allow -Enabled True

# Allow Netlogon (TCP 445)
New-NetFirewallRule -DisplayName "Allow Netlogon" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Enabled True

# Allow RDP (TCP 3389)
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Enabled True

# 4. Windows 10 (IIS) - 192.168.7.4
# Allow HTTP (TCP 80) and HTTPS (TCP 443)
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Enabled True
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Enabled True

# 5. SMB Windows Server - 192.168.7.3
# Allow SMB (TCP 445)
New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Enabled True

# ============================
# End of Firewall Rules
# ============================

# Note: This script needs to be run in an elevated PowerShell prompt (Run as Administrator).
# Review and adjust rules as necessary based on specific competition requirements.
