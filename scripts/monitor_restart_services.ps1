# Purpose: Monitor critical services and automatically restart if they fail.

# Pool of serveses: W3SVC (IIS), WinRM, LanmanServer (SMB), DNS.
$services = @("type", "service", "here")

foreach ($service in $services) {
    $serviceStatus = Get-Service -Name $service
    if ($serviceStatus.Status -ne 'Running') {
        Start-Service -Name $service
        Write-Output "$service restarted at $(Get-Date)"
    }
}