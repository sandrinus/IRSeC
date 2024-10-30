# Get all installed applications from the registry that match "Python"
$pythonPrograms = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "Python" }

# Check both 32-bit and 64-bit registry locations
$pythonPrograms32 = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "Python" }

$allPythonPrograms = $pythonPrograms + $pythonPrograms32

# Uninstall each Python installation found
foreach ($program in $allPythonPrograms) {
    Write-Output "Uninstalling: $($program.DisplayName)"
    
    # Run the uninstall command silently
    & cmd /c "$($program.UninstallString) /quiet /norestart"
    
    Write-Output "Uninstalled: $($program.DisplayName)"
}

Write-Output "Python uninstallation completed."
