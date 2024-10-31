Import-Module ActiveDirectory  # Loads the Active Directory module to enable AD user management functions

#Yo, so create csv file in format that is listed below. YOu don't need to input all domains for each users(I hope)
#it will check domain in the begining of the program and should input domain name for you. then it's just runs.
#if you need pause for longer then 5 min change it at the bottom bottum bottun fuck it i'm SCOTTISH!
#I honetly don't know if it's even going to work 

#CSV EXAMPLE:
#Username,Password,Domain
#jdoe,MySecurePassword1,example.com
#asmith,AnotherPassword2,example.com
#mwhite,YetAnotherPassword3,example.org


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

# Check if domain information is missing and update CSV if necessary
# If don't have domain yet it will try to check default domain. if it can't find domain good luck i finding it yourself 
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
        #SamAccountName -> used to uniquely identify and manage user accounts within scripts
        $adUser = $_.SamAccountName                                         # Gets the SAM account name of each user

        # If the AD user is not found in the CSV, delete the account
        if ($adUser -notin $usernamesFromCsv) {
            Remove-ADUser -Identity $adUser -Confirm:$false -ErrorAction Stop  # Deletes the user account without confirmation
        }
    }
}

# Infinite loop to run the sync function every 5 minutes
while ($true) {
    Sync-Users                                                              # Calls the function to synchronize users with the CSV file
    Start-Sleep -Seconds 300                                                # Waits 300 seconds (5 minutes) before the next sync
}