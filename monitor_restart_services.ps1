# Purpose: Monitor critical services (like IIS, SMB, WinRM) and automatically restart if they fail.

$services = @("W3SVC", "WinRM", "SMBServer")

foreach ($service in $services) {
    $serviceStatus = Get-Service -Name $service
    if ($serviceStatus.Status -ne 'Running') {
        Start-Service -Name $service
        Write-Output "$service restarted at $(Get-Date)" | Out-File "C:\ServiceLogs\RestartLog.txt" -Append
    }
}
