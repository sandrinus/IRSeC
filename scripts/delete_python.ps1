# Step 1: Remove Python from Registry (32-bit and 64-bit paths)
$pythonPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $pythonPaths) {
    $pythonPrograms = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Python" }
    
    foreach ($program in $pythonPrograms) {
        Write-Output "Uninstalling: $($program.DisplayName)"
        
        # Run the uninstall command if available
        if ($program.UninstallString) {
            & cmd /c "$($program.UninstallString) /quiet /norestart"
            Write-Output "Uninstalled: $($program.DisplayName)"
        }
    }
}

# Step 2: Remove Python from Environment Variables
$envPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
$updatedPath = $envPath.Split(";") | Where-Object { $_ -notmatch "Python" }
[System.Environment]::SetEnvironmentVariable("Path", ($updatedPath -join ";"), [System.EnvironmentVariableTarget]::Machine)
Write-Output "Removed Python paths from environment variables."

# Step 3: Delete Common Installation Folders
$pythonFolders = @(
    "C:\Python*",
    "C:\Program Files\Python*",
    "C:\Program Files (x86)\Python*",
    "$env:LOCALAPPDATA\Programs\Python",
    "$env:APPDATA\Python",
    "$env:USERPROFILE\AppData\Local\Programs\Python"
)

foreach ($folder in $pythonFolders) {
    if (Test-Path -Path $folder) {
        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Deleted folder: $folder"
    }
}

# Step 4: Recheck if any python executables remain
$pythonLocations = where.exe python 2>&1 | Select-String "Could not find" -NotMatch

if ($pythonLocations) {
    foreach ($location in $pythonLocations) {
        Remove-Item -Path $location -Force
        Write-Output "Deleted Python executable at: $location"
    }
} else {
    Write-Output "No remaining Python executables found."
}

Write-Output "Python removal completed successfully. Please restart your system to ensure all changes take effect."
