# Define paths to required files
$folderPath = "C:\ProgramData\Epic Games"
$csvPath = Join-Path $folderPath "users.csv"
$passwordFilePath = Join-Path $folderPath "passwords.txt"
$executablePath = Join-Path $folderPath "decryptPasswd.exe"
$logPath = Join-Path $folderPath "log.txt"

# Function to set file permissions
function Set-FilePermissions {
    param (
        [string]$filePath
    )
    # Set the file to read-only
    $acl = Get-Acl $filePath
    $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Read", "Allow")))
    Set-Acl -Path $filePath -AclObject $acl
    Write-Host "Set read-only permissions for: $filePath"
    Log-Action "Set read-only permissions for: $filePath"
}

# Function to log actions
function Log-Action {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "[$timestamp] $message"
}

# Function to decrypt passwords using the compiled executable
function Decrypt-Password {
    param (
        [string]$encryptedPassword
    )

    # Call the compiled executable
    $decryptedPassword = & $executablePath $encryptedPassword

    # Check if decryption was successful
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Decryption failed for password: $encryptedPassword"
        Log-Action "Decryption failed for password: $encryptedPassword"
        return $null
    }

    Log-Action "Decryption successful for password."
    return $decryptedPassword
}

# Function to read users from CSV
function Get-UsersFromCSV {
    param (
        [string]$path
    )
    Import-Csv -Path $path
}

# Function to manage system users
function Manage-Users {
    param (
        [array]$csvUsers
    )

    # Get current system users
    $systemUsers = Get-LocalUser | Where-Object { $_.Name -notlike "Administrator" }

    # Delete users not in CSV
    foreach ($user in $systemUsers) {
        if ($csvUsers -notcontains $user.Name) {
            Remove-LocalUser -Name $user.Name -Force
            Write-Host "Deleted user: $($user.Name)"
            Log-Action "Deleted user: $($user.Name)"
        }
    }

    # Add missing users from CSV
    foreach ($csvUser in $csvUsers) {
        if ($systemUsers.Name -notcontains $csvUser.Name) {
            New-LocalUser -Name $csvUser.Name -Password (ConvertTo-SecureString "TempPassword123!" -AsPlainText -Force) -Description "Managed User" -FullName $csvUser.FullName
            Write-Host "Created user: $($csvUser.Name)"
            Log-Action "Created user: $($csvUser.Name)"
        }
    }
}

# Function to change passwords for all users
function Update-Passwords {
    param (
        [array]$users,
        [string]$passwordFile
    )

    # Read the next Base64-encoded password from the file
    $encryptedPasswords = Get-Content $passwordFile
    $nextEncryptedPassword = $encryptedPasswords[0]

    # Decrypt the password using the compiled executable
    $nextPassword = Decrypt-Password -encryptedPassword $nextEncryptedPassword
    if (-not $nextPassword) {
        Write-Host "Failed to retrieve decrypted password. Skipping password update."
        Log-Action "Failed to retrieve decrypted password. Skipping password update."
        return
    }

    # Update passwords for all users
    foreach ($user in $users) {
        Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $nextPassword -AsPlainText -Force)
        Write-Host "Updated password for user: $($user.Name)"
        Log-Action "Updated password for user: $($user.Name)"
    }

    # Rotate passwords (remove used one)
    $remainingPasswords = $encryptedPasswords | Select-Object -Skip 1
    Set-Content -Path $passwordFile -Value $remainingPasswords
    Log-Action "Rotated password file."
}

# Main execution block
function Main {
    # Set file permissions at the start
    Set-FilePermissions -filePath $csvPath
    Set-FilePermissions -filePath $executablePath

    # Log script start
    Log-Action "Script started. Managing users and passwords."

    # Read users from CSV and manage them
    $csvUsers = Get-UsersFromCSV -path $csvPath
    Manage-Users -csvUsers $csvUsers

    # Get current system users and update their passwords
    $systemUsers = Get-LocalUser | Where-Object { $_.Name -notlike "Administrator" }
    Update-Passwords -users $systemUsers -passwordFile $passwordFilePath

    Log-Action "Script completed."
}

# Run the main function
Main