param([int]$LookbackMinutes = 15)

$lookbackMinutes = $LookbackMinutes
$startTime = (Get-Date).AddMinutes(-$lookbackMinutes)

$patterns = @{
    "Encoded command"          = '(?i)(?:^|\s)-(?:enc|encodedcommand)\b'
    "Execution policy bypass"  = '(?i)-ExecutionPolicy\s+Bypass\b'
    "Hidden window"            = '(?i)-WindowStyle\s+Hidden\b'
    "Invoke-Expression"        = '(?i)(?:Invoke-Expression|\bIEX\s*\()'
    "DownloadString"           = '(?i)DownloadString\s*\('
    "Invoke-WebRequest"        = '(?i)Invoke-WebRequest\b'
}

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
    $commandLine = $data['CommandLine']

    if ($image -notmatch '(?i)\\(?:powershell|pwsh)\.exe
    $matchedIndicators = @()

    foreach ($name in $patterns.Keys) {
        if ($commandLine -match $patterns[$name]) {
            $matchedIndicators += $name
        }
    }

    if ($matchedIndicators.Count -gt 0) {
        $alerts += [pscustomobject]@{
            TimeCreated       = $event.TimeCreated
            User              = $data['User']
            Image             = $image
            CommandLine       = $commandLine
            ParentImage       = $data['ParentImage']
            ParentCommandLine = $data['ParentCommandLine']
            ProcessId         = $data['ProcessId']
            ProcessGuid       = $data['ProcessGuid']
            Indicators        = ($matchedIndicators -join ', ')
            IndicatorCount    = $matchedIndicators.Count
        }
    }
}

if ($alerts.Count -eq 0) {
    Write-Host "No suspicious PowerShell activity detected in the last $lookbackMinutes minutes."
    exit
}

foreach ($alert in ($alerts | Sort-Object TimeCreated -Descending)) {
    Write-Host "ALERT: Suspicious PowerShell execution detected."
    Write-Host "Time: $($alert.TimeCreated)"
    Write-Host "User: $($alert.User)"
    Write-Host "Image: $($alert.Image)"
    Write-Host "CommandLine: $($alert.CommandLine)"
    Write-Host "ParentImage: $($alert.ParentImage)"
    Write-Host "ProcessId: $($alert.ProcessId)"
    Write-Host "ProcessGuid: $($alert.ProcessGuid)"
    Write-Host "Indicators: $($alert.Indicators)"
    Write-Host "Indicator count: $($alert.IndicatorCount)"
    Write-Host ""
}
) {
        continue
    }

    # Prevent the detector from alerting on its own PowerShell invocation.
    if ($commandLine -match '(?i)detect_suspicious_powershell\.ps1') {
        continue
    }

    $matchedIndicators = @()

    foreach ($name in $patterns.Keys) {
        if ($commandLine -match $patterns[$name]) {
            $matchedIndicators += $name
        }
    }

    if ($matchedIndicators.Count -gt 0) {
        $alerts += [pscustomobject]@{
            TimeCreated       = $event.TimeCreated
            User              = $data['User']
            Image             = $image
            CommandLine       = $commandLine
            ParentImage       = $data['ParentImage']
            ParentCommandLine = $data['ParentCommandLine']
            ProcessId         = $data['ProcessId']
            ProcessGuid       = $data['ProcessGuid']
            Indicators        = ($matchedIndicators -join ', ')
            IndicatorCount    = $matchedIndicators.Count
        }
    }
}

if ($alerts.Count -eq 0) {
    Write-Host "No suspicious PowerShell activity detected in the last $lookbackMinutes minutes."
    exit
}

foreach ($alert in ($alerts | Sort-Object TimeCreated -Descending)) {
    Write-Host "ALERT: Suspicious PowerShell execution detected."
    Write-Host "Time: $($alert.TimeCreated)"
    Write-Host "User: $($alert.User)"
    Write-Host "Image: $($alert.Image)"
    Write-Host "CommandLine: $($alert.CommandLine)"
    Write-Host "ParentImage: $($alert.ParentImage)"
    Write-Host "ProcessId: $($alert.ProcessId)"
    Write-Host "ProcessGuid: $($alert.ProcessGuid)"
    Write-Host "Indicators: $($alert.Indicators)"
    Write-Host "Indicator count: $($alert.IndicatorCount)"
    Write-Host ""
}
