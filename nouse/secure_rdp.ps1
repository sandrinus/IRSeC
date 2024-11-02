# Continue on error
$ErrorActionPreference = 'silentlycontinue'

# Require elevation for script run
Requires -RunAsAdministrator
Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

# Enable Network Level Authentication (NLA)
$NLAKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
Set-ItemProperty -Path $NLAKeyPath -Name "NLA" -Type DWORD -Value 1 -Force

# Disable RDP access to the built-in Administrator account
$AdminKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $AdminKeyPath -Name "AutoAdminLogon" -Value "0" -Force

# Set RDP to allow only specific users
$RDPUsersGroup = "Remote Desktop Users"
try {
    New-LocalGroup -Name $RDPUsersGroup -ErrorAction Stop
} catch {
    Write-Output "Remote Desktop Users group already exists."
}

# Add the current user to the Remote Desktop Users group
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Add-LocalGroupMember -Group $RDPUsersGroup -Member $CurrentUser

# Configure RDP to log off idle sessions after 15 minutes
$IdleSessionKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server"
Set-ItemProperty -Path $IdleSessionKeyPath -Name "MaxIdleTime" -Type DWORD -Value 900000 -Force # 15 minutes in milliseconds

# Enable auditing for logon events
$AuditKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $AuditKeyPath -Name "AuditLogon" -Type DWORD -Value 1 -Force

# Disable the RDP service if not needed (Uncomment if you want to disable it)
# Stop-Service -Name TermService -Force
# Set-Service -Name TermService -StartupType Disabled

Write-Output "RDP security settings have been applied."
