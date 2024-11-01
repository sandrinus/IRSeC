Import-Module ActiveDirectory  # Loads the Active Directory module to enable AD user management functions

# File paths
$userListPath = "C:\example\username.txt"   # File containing usernames, one per line
$passwordFilePath = "C:\example\password.txt" # File containing encrypted passwords, one per line
$passwordInUsePath = "C:\example\password_in_use.txt" # File to log the currently used password

# Placeholder for decryption function
function Decrypt-Password {
    param ([string]$encryptedPassword)
    # Decryption logic will be added here
    return $encryptedPassword  # Placeholder return
}

# Function to retrieve the AD domain
function Get-ActiveDirectoryDomain {
    try {
        $domain = (Get-ADDomain).DNSRoot
        return $domain
    }catch {
        Write-Host "Unable to retrieve Active Directory domain. Ensure this machine is connected to an AD environment."
        exit
    }
}

# Function to retrieve and delete the next encrypted password from password.txt
function Get-NextPassword {
    $passwordLines = Get-Content -Path $passwordFilePath

    if ($passwordLines.Count -gt 0) {
        $encryptedPassword = $passwordLines[0].Trim()
        $decryptedPassword = Decrypt-Password -encryptedPassword $encryptedPassword

        # Log the currently used encrypted password
        $encryptedPassword | Out-File -FilePath $passwordInUsePath -Force

        # Remove the used password line from the file
        $remainingLines = $passwordLines | Select-Object -Skip 1
        $remainingLines | Set-Content -Path $passwordFilePath

        return $decryptedPassword
    } else {
        Write-Host "No more passwords available in the file."
        exit
    }
}

# Function to synchronize users with username.txt and set/update passwords
function Sync-Users {
    $domain = Get-ActiveDirectoryDomain
    $password = ConvertTo-SecureString (Get-NextPassword) -AsPlainText -Force
    $userList = Get-Content -Path $userListPath
    $extraAdminUser = $userList[0].Trim()  # First user in username.txt is the extra admin

    # Remove users not listed in username.txt
    Get-ADUser -Filter * | ForEach-Object {
        $adUser = $_.SamAccountName
        if ($adUser -notin $userList) {
            Remove-ADUser -Identity $adUser -Confirm:$false -ErrorAction Stop
            Write-Host "User $adUser has been deleted as they were not in the username list."
        }
    }

    # Ensure the extra admin user is present, create if not found
    if (-not (Get-ADUser -Filter { SamAccountName -eq $extraAdminUser })) {
        New-ADUser -SamAccountName $extraAdminUser `
                   -UserPrincipalName "$extraAdminUser@$domain" `
                   -Name $extraAdminUser `
                   -GivenName $extraAdminUser `
                   -Surname "AdminUser" `
                   -AccountPassword $password `
                   -Enabled $true `
                   -PassThru -ErrorAction Stop
        Add-ADGroupMember -Identity "Domain Admins" -Members $extraAdminUser
        Write-Host "Admin user $extraAdminUser created and added to Domain Admins."
    }

    # Ensure all users in username.txt are present, create if missing, and update passwords
    foreach ($username in $userList) {
        $username = $username.Trim()

        if (-not (Get-ADUser -Filter { SamAccountName -eq $username })) {
            New-ADUser -SamAccountName $username `
                       -UserPrincipalName "$username@$domain" `
                       -Name $username `
                       -GivenName $username `
                       -Surname "User" `
                       -AccountPassword $password `
                       -Enabled $true `
                       -PassThru -ErrorAction Stop
            Write-Host "User $username created."
        } else {
            # Update password for existing user
            Set-ADUser -Identity $username -AccountPassword $password
            Write-Host "Password updated for $username."
        }
    }
}

# Infinite loop to sync users and update passwords every 30 minutes
while ($true) {
    Sync-Users                                                              # Calls the function to synchronize users
    Start-Sleep -Seconds 1800                                               # Waits 1800 seconds (30 minutes) before next sync
}