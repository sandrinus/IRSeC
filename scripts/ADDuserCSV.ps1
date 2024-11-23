Import-Module ActiveDirectory

# ты оговорил что у тебя будут чайники, так что я попросил чтобы гпт раздуплил по максимуму. сосал?
# --- Instructions for Running the Script ---
# Purpose:
# This script manages Active Directory (AD) user accounts by synchronizing them with a CSV file 
# and ensuring password rotation occurs every 30 minutes. It also logs the currently used password
# in a separate `password_in_use.txt` file for reference.

# How it works:
# 1. The script reads a `users.csv` file that contains:
#    - `Username`: The AD username.
#    - `Type`: Either "admin" (for admin accounts) or "regular" (for regular accounts).
#    - `Passwords`: A pipe-separated (`|`) list of passwords for the user.
# 2. Deletes any AD users that are not listed in the `users.csv`.
# 3. Ensures all users in the `users.csv` exist in AD with the correct type (admin/regular) and 
#    rotates their passwords to the next one in the list.
# 4. The current password in use for all accounts is logged in `password_in_use.txt`.
# 5. Password rotation happens every 30 minutes in an infinite loop until all passwords in the
#    list are used, then starts again from the first password.

# Example file structure:
# - `users.csv`: A CSV file with columns `Username`, `Type`, and `Passwords`.
#    Example:
#    ```
#    Username,Type,Passwords
#    user1,regular,password1|password2|password3
#    admin1,admin,password1|password2|password3
#    ```
# - `password_in_use.txt`: This file stores the password currently in use globally.

# Requirements:
# 1. Active Directory environment: The script requires access to an AD domain and the 
#    `ActiveDirectory` PowerShell module.
# 2. Run the script with administrative privileges: Ensure sufficient permissions to manage AD users.
# 3. Place the CSV and `password_in_use.txt` in accessible locations and update the file paths in the script.

# Running the Script:
# - Run the script as a user with administrative privileges.
# - Open PowerShell as Administrator, navigate to the directory where the script is located, and run:
#     .\YourScriptName.ps1
# - The script will run indefinitely, checking and updating AD users and passwords every 30 minutes.

# Notes:
# - The `password_in_use.txt` file is overwritten after each password rotation to reflect the current password in use.
# - The script skips built-in accounts (e.g., Administrator, Guest, krbtgt) during deletion.


# File paths
$csvFilePath = "C:\ProgramData\Epic Games\IRSeC\passwd\users.csv"
$passwordInUsePath = "C:\ProgramData\Epic Games\IRSeC\passwd\password_in_use.txt"

# Function to decrypt an encrypted password
function Decrypt-Password {
    param (
        [string]$encryptedPassword
    )
    $encryptedBytes = [Convert]::FromBase64String($encryptedPassword)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = [Convert]::FromBase64String("deqKCoV9HjSudP1nzF0KJg==")
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.IV = $aes.Key[0..15]
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
   
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

# Function to synchronize users
function Sync-Users {
    $domain = (Get-ADDomain).DNSRoot

    # Load users from CSV
    $users = Import-Csv -Path $csvFilePath

    # Step 1: Remove users not in the CSV
    $csvUsernames = $users.Username
    Get-ADUser -Filter * | ForEach-Object {
        $adUser = $_.SamAccountName
        if ($adUser -notin $csvUsernames -and $adUser -notmatch "^(Administrator|Guest|krbtgt)$") {
            Remove-ADUser -Identity $adUser -Confirm:$false -ErrorAction Stop
            Write-Host "Deleted user $adUser"
        }
    }

    foreach ($user in $users) {
        $username = $user.Username.Trim()
        if (-not $username -or $username -eq "") {
            Write-Host "Skipping user due to empty or invalid username."
            continue
        }
    
        # Validate and split passwords
        if ($user.Passwords -and $user.Passwords.Trim() -ne "") {
            $passwords = $user.Passwords.Split('|')
        } else {
            Write-Host "No passwords found for user $username. Skipping."
            continue
        }
    
        # Check for current password in use
        $passwordInUse = if (Test-Path $passwordInUsePath) {
            Get-Content -Path $passwordInUsePath
        } else {
            $passwords[0]
        }
    
        # Determine the next password
        if ($passwordInUse -and $passwords -and $passwords.Contains($passwordInUse)) {
            $nextPasswordIndex = ($passwords.IndexOf($passwordInUse) + 1) % $passwords.Count
            $newPassword = ConvertTo-SecureString $passwords[$nextPasswordIndex] -AsPlainText -Force
        } else {
            Write-Host "Invalid password or no rotation for user $username. Skipping."
            continue
        }
    
        # Check if user exists in AD
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
        if (-not $adUser) {
            # User does not exist; create the user
            New-ADUser -SamAccountName $username `
                       -UserPrincipalName "$username@$domain" `
                       -Name $username `
                       -GivenName $username `
                       -Surname "User" `
                       -AccountPassword $newPassword `
                       -Enabled $true `
                       -PassThru -ErrorAction Stop
            Write-Host "Created user $username."
        } else {
            # Update existing user's password
            Set-ADAccountPassword -Identity $username -NewPassword $newPassword -Reset
            Unlock-ADAccount -Identity $username
            Write-Host "Updated password for user $username."
        }
    }
    
    # Update the password_in_use.txt file
    $passwords[$nextPasswordIndex] | Out-File -FilePath $passwordInUsePath -Force
    Write-Host "Password in use updated to: $($passwords[$nextPasswordIndex])"    
}

# Infinite loop to synchronize users every 30 minutes
while ($true) {
    Sync-Users
    Start-Sleep -Seconds 1800
}
