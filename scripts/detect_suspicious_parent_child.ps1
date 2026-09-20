param(
    [int]$LookbackMinutes = 15
)

$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)

# Suspicious child processes commonly seen when launched by Office applications.
$suspiciousChildren = @(
    'powershell.exe',
    'pwsh.exe',
    'cmd.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe',
    'rundll32.exe',
    'regsvr32.exe'
)

# Office-style parent process names that are high-value for parent/child monitoring.
$officeParents = @(
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe',
    'onenote.exe'
)

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 1
    StartTime = $startTime
}

$alerts = @()

foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $data = @{}

    foreach ($node in $xml.Event.EventData.Data) {
        $data[$node.Name] = [string]$node.'#text'
    }

    $image = $data['Image']
    $parentImage = $data['ParentImage']

    if (-not $image -or -not $parentImage) {
        continue
    }

    $childName = [System.IO.Path]::GetFileName($image).ToLower()
    $parentName = [System.IO.Path]::GetFileName($parentImage).ToLower()

    if (($officeParents -contains $parentName) -and ($suspiciousChildren -contains $childName)) {
        $alerts += [pscustomobject]@{
            TimeCreated       = $event.TimeCreated
            User              = $data['User']
            ParentImage       = $parentImage
            ParentCommandLine = $data['ParentCommandLine']
            Image             = $image
            CommandLine       = $data['CommandLine']
            ProcessId         = $data['ProcessId']
            ProcessGuid       = $data['ProcessGuid']
        }
    }
}

if ($alerts.Count -eq 0) {
    Write-Host "No suspicious Office parent/child process activity detected in the last $LookbackMinutes minutes."
    exit
}

foreach ($alert in ($alerts | Sort-Object TimeCreated -Descending)) {
    Write-Host "ALERT: Suspicious parent/child process relationship detected."
    Write-Host "Time: $($alert.TimeCreated)"
    Write-Host "User: $($alert.User)"
    Write-Host "ParentImage: $($alert.ParentImage)"
    Write-Host "ParentCommandLine: $($alert.ParentCommandLine)"
    Write-Host "Image: $($alert.Image)"
    Write-Host "CommandLine: $($alert.CommandLine)"
    Write-Host "ProcessId: $($alert.ProcessId)"
    Write-Host "ProcessGuid: $($alert.ProcessGuid)"
    Write-Host ""
}
