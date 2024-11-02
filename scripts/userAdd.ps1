Import-Module ActiveDirectory  # Loads the Active Directory module to enable AD user management functions

# --- Instructions for Running the Script ---
# Run the Script with Sufficient Permissions:
# - Permissions: Run the script as a user with administrative privileges on an AD server
#   or from a client with sufficient rights to manage AD users.
# - Execution Policy: Ensure PowerShell allows script execution. You might need to set the policy with:
#     Set-ExecutionPolicy RemoteSigned
# - Execution: Open PowerShell as Administrator, navigate to the directory where the script is located, and run it:
#     .\YourScriptName.ps1
# ------------------------------------------------------------

# Create the necessary files: username.txt, admin_users.txt, all_users.txt, password.txt, and password_in_use.txt
# Specify the file paths in the code below.

# Example content for username.txt (regular users):
# user1
# user2

# Example content for admin_users.txt (admin users):
# backupAdmin
# adminUser2

# Example content for all_users.txt (contains both regular and admin users):
# user1
# user2
# backupAdmin
# adminUser2

# Example content for password.txt (encrypted passwords in base64 format):
# ENCRYPTED_PASSWORD_1
# ENCRYPTED_PASSWORD_2
# ENCRYPTED_PASSWORD_3

# Specify file paths for user lists and password management
$userListPath = "C:\ProgramData\Epic Games\IRSeC-test\passwd\username.txt"           # File containing regular usernames, one per line
$adminUserListPath = "C:\ProgramData\Epic Games\IRSeC-test\passwd\admin_users.txt"    # File containing admin usernames, one per line
$allUsersPath = "C:\ProgramData\Epic Games\IRSeC-test\passwd\all_users.txt"           # File containing all users to be kept in the system
$passwordFilePath = "C:\ProgramData\Epic Games\IRSeC-test\passwd\password.txt"        # File containing encrypted passwords, one per line
$passwordInUsePath = "C:\ProgramData\Epic Games\IRSeC-test\passwd\password_in_use.txt" # File to log the currently used password

# Hardcoded AES key for decryption (base64 encoded key provided by the user)
$SecretKey = [Convert]::FromBase64String("deqKCoV9HjSudP1nzF0KJg==")

# Function to decrypt an encrypted password
function Decrypt-Password {
    param (
        [string]$encryptedPassword  # The encrypted password in base64 format
    )

    # Convert the encrypted password from base64 to bytes
    $encryptedBytes = [Convert]::FromBase64String($encryptedPassword)

    # Initialize AES decryption settings
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $SecretKey
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    # Define a static IV by taking the first 16 bytes of the key
    $aes.IV = $SecretKey[0..15]

    # Create decryptor and decrypt the password
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

    # Convert decrypted bytes to plaintext password
    $decryptedPassword = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    return $decryptedPassword
}

# Function to retrieve the AD domain
function Get-ActiveDirectoryDomain {
    try {
        # Retrieve the AD domain's DNS root for this environment
        $domain = (Get-ADDomain).DNSRoot
        return $domain
    } catch {
        Write-Host "Unable to retrieve Active Directory domain. Ensure this machine is connected to an AD environment."
        exit
    }
}

# Function to retrieve and delete the next encrypted password from password.txt
function Get-NextPassword {
    # Read the password file content
    $passwordLines = Get-Content -Path $passwordFilePath

    # Check if there are passwords available
    if ($passwordLines.Count -gt 0) {
        # Take the first password from the file
        $encryptedPassword = $passwordLines[0].Trim()
        $decryptedPassword = Decrypt-Password -encryptedPassword $encryptedPassword

        # Log the currently used encrypted password in password_in_use.txt
        $encryptedPassword | Out-File -FilePath $passwordInUsePath -Force

        # Remove the used password line from password.txt
        $remainingLines = $passwordLines | Select-Object -Skip 1
        $remainingLines | Set-Content -Path $passwordFilePath

        return $decryptedPassword
    } else {
        Write-Host "No more passwords available in the file."
        exit
    }
}

# Function to synchronize users with admin_users.txt and username.txt and set/update passwords
function Sync-Users {
    # Retrieve the AD domain
    $domain = Get-ActiveDirectoryDomain

    # Get the next decrypted password for user account updates
    $password = ConvertTo-SecureString (Get-NextPassword) -AsPlainText -Force

    # Read the username lists from username.txt, admin_users.txt, and all_users.txt
    $regularUsers = Get-Content -Path $userListPath
    $adminUsers = Get-Content -Path $adminUserListPath
    $allUsers = Get-Content -Path $allUsersPath

    # Step 1: Remove any AD users not listed in all_users.txt, skipping built-in accounts
    Get-ADUser -Filter * | ForEach-Object {
        $adUser = $_.SamAccountName
        if ($adUser -notin $allUsers -and $adUser -notmatch "^(Administrator|Guest|krbtgt)$") {
            Remove-ADUser -Identity $adUser -Confirm:$false -ErrorAction Stop
            Write-Host "User $adUser has been deleted as they were not in the all_users list."
        }
    }

    # Step 2: Ensure all admin users exist and have the latest password
    foreach ($adminUser in $adminUsers) {
        $adminUser = $adminUser.Trim()

        # Create the admin user if they do not already exist
        if (-not (Get-ADUser -Filter { SamAccountName -eq $adminUser })) {
            New-ADUser -SamAccountName $adminUser `
                       -UserPrincipalName "$adminUser@$domain" `
                       -Name $adminUser `
                       -GivenName $adminUser `
                       -Surname "AdminUser" `
                       -AccountPassword $password `
                       -Enabled $true `
                       -PassThru -ErrorAction Stop
            Add-ADGroupMember -Identity "Domain Admins" -Members $adminUser
            Write-Host "Admin user $adminUser created and added to Domain Admins."
        } else {
            # Update password for existing admin users using Set-ADAccountPassword
            Set-ADAccountPassword -Identity $adminUser -NewPassword $password -Reset
            Unlock-ADAccount -Identity $adminUser
            Write-Host "Password updated for admin user $adminUser."
        }
    }

    # Step 3: Ensure all regular users exist and have the latest password
    foreach ($regularUser in $regularUsers) {
        $regularUser = $regularUser.Trim()

        # Create the regular user if they do not already exist
        if (-not (Get-ADUser -Filter { SamAccountName -eq $regularUser })) {
            New-ADUser -SamAccountName $regularUser `
                       -UserPrincipalName "$regularUser@$domain" `
                       -Name $regularUser `
                       -GivenName $regularUser `
                       -Surname "User" `
                       -AccountPassword $password `
                       -Enabled $true `
                       -PassThru -ErrorAction Stop
            Write-Host "Regular user $regularUser created."
        } else {
            # Update password for existing regular users using Set-ADAccountPassword
            Set-ADAccountPassword -Identity $regularUser -NewPassword $password -Reset
            Unlock-ADAccount -Identity $regularUser
            Write-Host "Password updated for regular user $regularUser."
        }
    }
}

# Infinite loop to sync users and update passwords every 30 minutes
while ($true) {
    Sync-Users                                                              # Calls the function to synchronize users
    Start-Sleep -Seconds 1800                                               # Waits 1800 seconds (30 minutes) before next sync
}