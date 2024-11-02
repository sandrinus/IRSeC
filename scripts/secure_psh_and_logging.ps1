# Continue on error
$ErrorActionPreference = 'silentlycontinue'

#Disable CMD Interactive and CMD Inline 
reg add HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 1 /f

#Automatically exit CMD when opened
reg add "HKEY_CURRENT_USER\Software\Microsoft\Command Processor" /v AutoRun /t REG_EXPAND_SZ /d "exit"

#Disable Powershell v2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
# Require elevation for script run
Write-Output "Elevating privileges for this process"
Start-Process powershell.exe -ArgumentList "-Command { Start-Process powershell.exe -Verb RunAs }"

# Ensure the PowerShell Transcription logging registry path exists
if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "Transcription" -Force
}

# Create the logging directory if it doesn't exist
$logPath = "C:\ProgramData\Blizzard\PowershellLogs"
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force
}

# Set Output Directory for PowerShell Transcription
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Type String -Value $logPath -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Type DWORD -Value "1" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Type DWORD -Value "1" -Force

# Enable Script Block Logging to log all executed script blocks
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ScriptBlockLogging" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWORD -Value "1" -Force

# Enable Module Logging to capture detailed command execution within PowerShell modules
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ModuleLogging" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Type DWORD -Value "1" -Force

# Specify modules to log in Module Logging
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "ModuleNames" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Type String -Value "*" -Force

Write-Output "PowerShell logging has been enabled. Logs will be saved to $logPath."
