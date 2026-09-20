$threshold = 3

$events = Get-WinEvent -LogName "OpenSSH/Operational" |
    Where-Object { $_.Message -match "Invalid user (\S+) from (\S+) port" }

$activity = @{}

foreach ($event in $events) {
    if ($event.Message -match "Invalid user (\S+) from (\S+) port") {
        $username = $matches[1]
        $sourceIp = $matches[2]

        if (-not $activity.ContainsKey($sourceIp)) {
            $activity[$sourceIp] = @{
                Attempts  = 0
                Usernames = New-Object System.Collections.Generic.HashSet[string]
            }
        }

        $activity[$sourceIp].Attempts++
        [void]$activity[$sourceIp].Usernames.Add($username)
    }
}

$alertFound = $false

foreach ($sourceIp in $activity.Keys) {
    $uniqueUsers = $activity[$sourceIp].Usernames

    if ($uniqueUsers.Count -ge $threshold) {
        $alertFound = $true

        Write-Host "ALERT: Possible password spraying detected."
        Write-Host "Source IP: $sourceIp"
        Write-Host "Failed login attempts: $($activity[$sourceIp].Attempts)"
        Write-Host "Unique usernames targeted: $($uniqueUsers.Count)"
        Write-Host "Usernames: $(([string[]]$uniqueUsers | Sort-Object) -join ', ')"
        Write-Host ""
    }
}

if (-not $alertFound) {
    Write-Host "No password spraying pattern detected."
}
