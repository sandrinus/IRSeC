
# Define parameters
Param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("ad", "winrm", "ping", "smb", "iis")]
    [string]$Role
)

# Configure firewall rules based on the role
if ($Role -eq "ad") {
    # Define allowed inbound ports
    $InboundTCPPorts = @(53, 135, 389, 445)
    $InboundUDPPorts = @(53, 389)
    $HighPortRange = "49152-65535"

    # Allow ICMP (Ping)
    Write-Output "Allowing ICMP (Ping)..."
    New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4 -IcmpType 8 -Action Allow -Direction Inbound

    # Allow inbound TCP ports
    Write-Output "Allowing inbound TCP ports: $InboundTCPPorts and High Port Range ($HighPortRange)..."
    foreach ($port in $InboundTCPPorts) {
        New-NetFirewallRule -DisplayName "Allow TCP Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow
    }

    # Allow inbound high port range for RPC communication
    New-NetFirewallRule -DisplayName "Allow RPC High Ports" -Direction Inbound -Protocol TCP -LocalPort $HighPortRange -Action Allow

    # Allow inbound UDP ports
    Write-Output "Allowing inbound UDP ports: $InboundUDPPorts..."
    foreach ($port in $InboundUDPPorts) {
        New-NetFirewallRule -DisplayName "Allow UDP Port $port" -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow
    }

    # Allow DNS outbound traffic
    Write-Output "Allowing outbound DNS traffic..."
    New-NetFirewallRule -DisplayName "Allow Outbound DNS (TCP)" -Direction Outbound -Protocol TCP -RemotePort 53 -Action Allow
    New-NetFirewallRule -DisplayName "Allow Outbound DNS (UDP)" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow

    # Allow RPC outbound traffic
    Write-Output "Allowing outbound RPC traffic..."
    New-NetFirewallRule -DisplayName "Allow Outbound RPC" -Direction Outbound -Protocol TCP -RemotePort 135 -Action Allow

    # Allow SMB outbound traffic
    Write-Output "Allowing outbound SMB traffic..."
    New-NetFirewallRule -DisplayName "Allow Outbound SMB (TCP 445)" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Allow

    # Block all other inbound traffic
    Write-Output "Blocking all other inbound traffic..."
    New-NetFirewallRule -DisplayName "Block All Other Inbound Traffic" -Direction Inbound -Action Block

    # Block all other outbound traffic (if needed, comment this out if unrestricted outbound is required)
    Write-Output "Blocking all other outbound traffic..."
    New-NetFirewallRule -DisplayName "Block All Other Outbound Traffic" -Direction Outbound -Action Block

    Write-Output "Firewall rules configured successfully."
}

elseif ($Role -eq "winrm") {
    # Define Allowed Ports for WinRM and Domain Communication
$allowedInboundPorts = @(
    @{ Name = "WinRM HTTP"; Protocol = "TCP"; Port = 5985 },
    @{ Name = "WinRM HTTPS"; Protocol = "TCP"; Port = 5986 },
    @{ Name = "DNS Query"; Protocol = "UDP"; Port = 53 },
    @{ Name = "LDAP"; Protocol = "TCP"; Port = 389 }
)

$allowedOutboundPorts = @(
    @{ Name = "WinRM HTTP"; Protocol = "TCP"; Port = 5985 },
    @{ Name = "WinRM HTTPS"; Protocol = "TCP"; Port = 5986 },
    @{ Name = "DNS Query"; Protocol = "UDP"; Port = 53 },
    @{ Name = "LDAP"; Protocol = "TCP"; Port = 389 }
)

# Block all inbound traffic by default
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block

# Block all outbound traffic by default
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block

# Allow specific inbound rules
foreach ($rule in $allowedInboundPorts) {
    New-NetFirewallRule -DisplayName $rule.Name `
        -Direction Inbound `
        -Protocol $rule.Protocol `
        -LocalPort $rule.Port `
        -Action Allow `
        -Profile Domain,Private
}

# Allow specific outbound rules
foreach ($rule in $allowedOutboundPorts) {
    New-NetFirewallRule -DisplayName $rule.Name `
        -Direction Outbound `
        -Protocol $rule.Protocol `
        -LocalPort $rule.Port `
        -Action Allow `
        -Profile Domain,Private
}

Write-Host "Firewall rules configured for Warehead."
}
elseif ($Role -eq "ping") {
    # Define Allowed ICMP and Domain Ports
$allowedInboundRules = @(
    @{ Name = "ICMP Allow"; Protocol = "ICMPv4"; Port = 0 },
    @{ Name = "DNS Query"; Protocol = "UDP"; Port = 53 },
    @{ Name = "LDAP"; Protocol = "TCP"; Port = 389 }
)

$allowedOutboundRules = @(
    @{ Name = "ICMP Allow"; Protocol = "ICMPv4"; Port = 0 },
    @{ Name = "DNS Query"; Protocol = "UDP"; Port = 53 },
    @{ Name = "LDAP"; Protocol = "TCP"; Port = 389 }
)

# Block all inbound traffic by default
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block

# Block all outbound traffic by default
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block

# Allow specific inbound rules
foreach ($rule in $allowedInboundRules) {
    if ($rule.Protocol -eq "ICMPv4") {
        New-NetFirewallRule -DisplayName $rule.Name `
            -Direction Inbound `
            -Protocol $rule.Protocol `
            -Action Allow `
            -Profile Domain,Private
    } else {
        New-NetFirewallRule -DisplayName $rule.Name `
            -Direction Inbound `
            -Protocol $rule.Protocol `
            -LocalPort $rule.Port `
            -Action Allow `
            -Profile Domain,Private
    }
}

# Allow specific outbound rules
foreach ($rule in $allowedOutboundRules) {
    if ($rule.Protocol -eq "ICMPv4") {
        New-NetFirewallRule -DisplayName $rule.Name `
            -Direction Outbound `
            -Protocol $rule.Protocol `
            -Action Allow `
            -Profile Domain,Private
    } else {
        New-NetFirewallRule -DisplayName $rule.Name `
            -Direction Outbound `
            -Protocol $rule.Protocol `
            -LocalPort $rule.Port `
            -Action Allow `
            -Profile Domain,Private
    }
}

Write-Host "Firewall rules configured for radar."
}
elseif ($Role -eq "smb") {
    # Define Allowed Ports
$allowedInboundPorts = @(
    @{ Name = "SMB TCP"; Protocol = "TCP"; Port = 445 },
    @{ Name = "SMB UDP"; Protocol = "UDP"; Port = 445 },
    @{ Name = "RDP"; Protocol = "TCP"; Port = 3389 },
    @{ Name = "DNS Query"; Protocol = "UDP"; Port = 53 },
    @{ Name = "LDAP"; Protocol = "TCP"; Port = 389 }
)

$allowedOutboundPorts = @(
    @{ Name = "SMB TCP"; Protocol = "TCP"; Port = 445 },
    @{ Name = "SMB UDP"; Protocol = "UDP"; Port = 445 },
    @{ Name = "RDP"; Protocol = "TCP"; Port = 3389 },
    @{ Name = "DNS Query"; Protocol = "UDP"; Port = 53 },
    @{ Name = "LDAP"; Protocol = "TCP"; Port = 389 }
)

# Block all inbound traffic by default
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block

# Block all outbound traffic by default
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block

# Allow specific inbound rules
foreach ($rule in $allowedInboundPorts) {
    New-NetFirewallRule -DisplayName $rule.Name `
        -Direction Inbound `
        -Protocol $rule.Protocol `
        -LocalPort $rule.Port `
        -Action Allow `
        -Profile Domain,Private
}

# Allow specific outbound rules
foreach ($rule in $allowedOutboundPorts) {
    New-NetFirewallRule -DisplayName $rule.Name `
        -Direction Outbound `
        -Protocol $rule.Protocol `
        -LocalPort $rule.Port `
        -Action Allow `
        -Profile Domain,Private
}

Write-Host "Firewall rules configured for Submarine."
}
elseif ($Role -eq "iis") {
    # Define Allowed Ports
$allowedInboundPorts = @(
    @{ Name = "HTTP"; Protocol = "TCP"; Port = 80 },
    @{ Name = "HTTPS"; Protocol = "TCP"; Port = 443 },
    @{ Name = "RDP"; Protocol = "TCP"; Port = 3389 },
    @{ Name = "DNS Query"; Protocol = "UDP"; Port = 53 },
    @{ Name = "LDAP"; Protocol = "TCP"; Port = 389 }
)

$allowedOutboundPorts = @(
    @{ Name = "HTTP"; Protocol = "TCP"; Port = 80 },
    @{ Name = "HTTPS"; Protocol = "TCP"; Port = 443 },
    @{ Name = "RDP"; Protocol = "TCP"; Port = 3389 },
    @{ Name = "DNS Query"; Protocol = "UDP"; Port = 53 },
    @{ Name = "LDAP"; Protocol = "TCP"; Port = 389 }
)

# Block all inbound traffic by default
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block

# Block all outbound traffic by default
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block

# Allow specific inbound rules
foreach ($rule in $allowedInboundPorts) {
    New-NetFirewallRule -DisplayName $rule.Name `
        -Direction Inbound `
        -Protocol $rule.Protocol `
        -LocalPort $rule.Port `
        -Action Allow `
        -Profile Domain,Private
}

# Allow specific outbound rules
foreach ($rule in $allowedOutboundPorts) {
    New-NetFirewallRule -DisplayName $rule.Name `
        -Direction Outbound `
        -Protocol $rule.Protocol `
        -LocalPort $rule.Port `
        -Action Allow `
        -Profile Domain,Private
}

Write-Host "Firewall rules configured for Diplomat."

}