Import-Module ActiveDirectory  # Loads the Active Directory module to enable AD user management functions

# Yo, so create a usernames.txt file with each username on a new line.
# The program will automatically retrieve the domain name, so you don’t need to include it for each user.
# Passwords will be rotated from a separate password file (passwords.txt) every hour for added security.
# If you need a pause for longer than 1 hour, you can change it at the bottom. 
# Honestly, I don’t know if it’s even going to work, but I’m SCOTTISH and we’ll make it work!

# USERNAMES EXAMPLE (usernames.txt):
# wcyd
# gdigdagda
# ligma

# PASSWORDS EXAMPLE (passwords.txt):
# 1. EncryptedPassword1; DecryptedPassword1
# 2. EncryptedPassword2; DecryptedPassword2
# (This file will have 25 encrypted and decrypted passwords for rotation)

# Sets the paths to the files containing usernames and password details
$userListPath = "C:\example\usernames.txt"   # Text file with usernames, one per line
$passwordFilePath = "C:\example\passwords.txt" # Text file with password pairs (e.g., [number. encrypted password; decrypted password])

# Initial domain retrieval for consistency across users
$domain = Get-ActiveDirectoryDomain


# Placeholder for decryption function
function Decrypt-Password {
    param (
        [string]$encryptedPassword
    )
    # TODO - implement decrypt lmao
    return $encryptedPassword
}

# Function to retrieve the AD domain if it's not specified in the user file
function Get-ActiveDirectoryDomain {
    try {
        # Get the default AD domain for the current environment
        $domain = (Get-ADDomain).DNSRoot
        return $domain
    } catch {
        Write-Host "Unable to retrieve Active Directory domain. Ensure this machine is connected to an AD environment."
        exit
    }
}

# Function to retrieve and delete the next encrypted password from the password file
function Get-NextPassword {
    # Read the content of the password file
    $passwordLines = Get-Content -Path $passwordFilePath

    if ($passwordLines.Count -gt 0) {
        # Take the first encrypted password from the file
        $encryptedPassword = $passwordLines[0].Trim()
        $decryptedPassword = Decrypt-Password -encryptedPassword $encryptedPassword

        # Delete the used password line from the file
        $remainingLines = $passwordLines | Select-Object -Skip 1
        $remainingLines | Set-Content -Path $passwordFilePath

        return $decryptedPassword
    } else {
        Write-Host "No more passwords available in the file."
        exit
    }
}

# Function to create or update all users
function Sync-Users {
    # Reads the domain once and uses it for all users
    $domain = Get-ActiveDirectoryDomain
    $password = ConvertTo-SecureString (Get-NextPassword) -AsPlainText -Force
    $userList = Get-Content -Path $userListPath

    # Loop through each entry in the username file to ensure these users are in AD
    foreach ($username in $userList) {
        $username = $username.Trim()  # Retrieve and clean up each username

        # Checks if the user already exists in AD; if not, creates it
        if (-not (Get-ADUser -Filter { SamAccountName -eq $username })) {
            New-ADUser -SamAccountName $username `                          # Sets the user's logon name
                       -UserPrincipalName "$username@$domain" `             # Sets login name using domain from variable
                       -Name $username `                                    # Sets full name of the user
                       -GivenName $username `                               # Sets first name
                       -Surname "User" `                                    # Sets last name as "User" (can be adjusted)
                       -AccountPassword $password `                         # Assigns the user’s password
                       -Enabled $true `                                     # Enables the user account
                       -PassThru -ErrorAction Stop                          # Returns user object on success, stops on error
        } else {
            # Update the password for the existing user
            Set-ADUser -Identity $username -AccountPassword $password
            Write-Host "Password updated for $username."
        }
    }

    # Loop through each existing AD user and check if they are in the username list
    Get-ADUser -Filter * | ForEach-Object {
        $adUser = $_.SamAccountName  # Gets the SAM account name of each user

        # If the AD user is not found in the username list, delete the account
        if ($adUser -notin $userList) {
            Remove-ADUser -Identity $adUser -Confirm:$false -ErrorAction Stop  # Deletes the user account without confirmation
            Write-Host "User $adUser has been deleted as they were not in the username list."
        }
    }
}


# Infinite loop to sync users and update passwords every hour
while ($true) {
    Sync-Users                                                              # Calls the function to synchronize users with the username file
    Start-Sleep -Seconds 1800                                               # Waits 1800 seconds (1/2 hour) before the next sync
}
