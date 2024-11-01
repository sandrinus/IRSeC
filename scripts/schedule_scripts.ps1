# This script puts other scripts on a schedule to automate them.

# Array of paths to the scripts you want to run
$scriptPaths = @(
    "C:\ProgramData\Epic Games\IRSeC\scripts"
)

# Define the base task name
$baseTaskName = "TaskTo"

foreach ($scriptPath in $scriptPaths) {
    # Extract the script name to create a unique task name
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($scriptPath)
    $taskName = "$baseTaskName-$scriptName"

    # Check if the task already exists
    $taskExists = Get-ScheduledTask | Where-Object { $_.TaskName -eq $taskName }

    if ($taskExists) {
        # If the task exists, update it to run every minute
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup -RepeatIndefinitely -Once -Interval (New-TimeSpan -Minutes 1)
        Set-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger
    } else {
        # If the task does not exist, create it
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup -RepeatIndefinitely -Once -Interval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User "SYSTEM"
    }

    Write-Output "Scheduled task '$taskName' has been configured to run every minute."
}
