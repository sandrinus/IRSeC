Import-Module ActiveDirectory  # Loads the Active Directory module to enable AD user management functions

# Yo, so create CSV file in format that is listed below. You don't need to input all domains for each user (I hope).
# It will check the domain at the beginning of the program and should input the domain name for you. Then it just runs.
# If you need a pause for longer than 5 minutes, change it at the bottom. Button, bottom, bottun... screw it, I'm SCOTTISH!
# I honestly don't know if it's even going to work


#hends up add admin user name and use same password for it as for other users
# CSV EXAMPLE:
# Username,Password,Domain
# jdoe,MySecurePassword1,example.com
# asmith,AnotherPassword2,example.com
# mwhite,YetAnotherPassword3,example.org

# Sets the path to the CSV file containing user account details
$userListPath = "C:\example\filename.csv"

# Function to retrieve the AD domain if it's not specified in the CSV
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

# Function to create an admin user
function Create-AdminUser {
    param (
        [string]$AdminUsername = "AdminUser",         # Default admin username
        [string]$AdminPassword = "SuperSecurePass1",  # Default admin password
        [string]$AdminGroup = "Domain Admins"         # Group to add the admin user to
    )

    $password = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $domain = Get-ActiveDirectoryDomain

    # Check if the admin user already exists
    if (-not (Get-ADUser -Filter { SamAccountName -eq $AdminUsername })) {
        # Create the admin user
        New-ADUser -SamAccountName $AdminUsername `
                   -UserPrincipalName "$AdminUsername@$domain" `
                   -Name $AdminUsername `
                   -GivenName "Admin" `
                   -Surname "User" `
                   -AccountPassword $password `
                   -Enabled $true `
                   -PassThru -ErrorAction Stop

        Write-Host "Admin user $AdminUsername created successfully."

        # Add the admin user to the specified group
        Add-ADGroupMember -Identity $AdminGroup -Members $AdminUsername
        Write-Host "Admin user $AdminUsername added to $AdminGroup."
    } else {
        Write-Host "Admin user $AdminUsername already exists."
    }
}

# Check if domain information is missing and update CSV if necessary
# If domain info is missing, it will try to use the default domain.
function Update-CsvWithDomain {
    # Get the current domain
    $currentDomain = Get-ActiveDirectoryDomain
    
    # Read the CSV file
    $userList = Import-Csv -Path $userListPath

    # Check if any entries are missing the Domain field
    $isUpdateNeeded = $userList | Where-Object { -not $_.Domain }

    if ($isUpdateNeeded) {
        # Add the domain to each user entry if the domain is missing
        $updatedUserList = $userList | ForEach-Object {
            if (-not $_.Domain) { $_.Domain = $currentDomain }
            $_
        }
        
        # Save the updated list back to the CSV file
        $updatedUserList | Export-Csv -Path $userListPath -NoTypeInformation -Force
        Write-Host "CSV file updated with domain: $currentDomain for all users."
    } else {
        Write-Host "All entries already contain domain information."
    }
}

# Function to synchronize users
function Sync-Users {
    # Reads user data from the CSV file. The CSV is expected to have columns: Username, Password, Domain
    $userList = Import-Csv -Path $userListPath

    # Extracts usernames from the CSV file into a list for quick lookups
    $usernamesFromCsv = $userList | Select-Object -ExpandProperty Username

    # Loop through each entry in the CSV to ensure these users are in AD
    foreach ($user in $userList) {
        $username = $user.Username  # Retrieves the username
        $password = ConvertTo-SecureString $user.Password -AsPlainText -Force  # Converts password to SecureString
        $domain = $user.Domain  # Retrieves the domain for setting the UserPrincipalName

        # Checks if the user already exists in AD; if not, creates it
        if (-not (Get-ADUser -Filter { SamAccountName -eq $username })) {
            New-ADUser -SamAccountName $username `                          # Sets the user's logon name
                       -UserPrincipalName "$username@$domain" `             # Sets login name using domain from CSV
                       -Name $username `                                    # Sets full name of the user
                       -GivenName $username `                               # Sets first name
                       -Surname "User" `                                    # Sets last name as "User" (can be adjusted)
                       -AccountPassword $password `                         # Assigns the user’s password
                       -Enabled $true `                                     # Enables the user account
                       -PassThru -ErrorAction Stop                          # Returns user object on success, stops on error
        }
    }

    # Loop through each existing AD user and check if they are in the CSV list
    Get-ADUser -Filter * | ForEach-Object {
        $adUser = $_.SamAccountName  # Gets the SAM account name of each user

        # If the AD user is not found in the CSV, delete the account
        if ($adUser -notin $usernamesFromCsv) {
            Remove-ADUser -Identity $adUser -Confirm:$false -ErrorAction Stop  # Deletes the user account without confirmation
            Write-Host "User $adUser has been deleted as they were not in the CSV."
        }
    }
}

# Initial setup
Update-CsvWithDomain  # Update CSV with domain if needed
Create-AdminUser      # Create an admin user if it doesn't exist

# Infinite loop to run the sync function every 5 minutes
while ($true) {
    Sync-Users                                                              # Calls the function to synchronize users with the CSV file
    Start-Sleep -Seconds 300                                                # Waits 300 seconds (5 minutes) before the next sync
}
