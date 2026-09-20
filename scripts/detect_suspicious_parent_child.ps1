param(
    [int]$LookbackMinutes = 15,
    [switch]$TestMode
)

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

$officeParents = @(
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe',
    'onenote.exe'
)

$records = @()

if ($TestMode) {
    $records += [pscustomobject]@{
        TimeCreated       = Get-Date
        User              = 'LAB\student'
        ParentImage       = 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'
        ParentCommandLine = '"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" C:\Lab\sample.docx'
        Image             = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        CommandLine       = 'powershell.exe -NoProfile -Command "Write-Output SOC-LAB-PARENT-CHILD-TEST"'
        ProcessId         = '4242'
        ProcessGuid       = '{00000000-0000-0000-0000-000000004242}'
    }
}
else {
    $startTime = (Get-Date).AddMinutes(-$LookbackMinutes)

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Sysmon/Operational'
        Id        = 1
        StartTime = $startTime
    }

    foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $data = @{}

        foreach ($node in $xml.Event.EventData.Data) {
            $data[$node.Name] = [string]$node.'#text'
        }

        $records += [pscustomobject]@{
            TimeCreated       = $event.TimeCreated
            User              = $data['User']
            ParentImage       = $data['ParentImage']
            ParentCommandLine = $data['ParentCommandLine']
            Image             = $data['Image']
            CommandLine       = $data['CommandLine']
            ProcessId         = $data['ProcessId']
            ProcessGuid       = $data['ProcessGuid']
        }
    }
}

$alerts = @()

foreach ($record in $records) {
    if (-not $record.Image -or -not $record.ParentImage) {
        continue
    }

    $childName = [System.IO.Path]::GetFileName($record.Image).ToLower()
    $parentName = [System.IO.Path]::GetFileName($record.ParentImage).ToLower()

    if (($officeParents -contains $parentName) -and ($suspiciousChildren -contains $childName)) {
        $alerts += $record
    }
}

if ($alerts.Count -eq 0) {
    if ($TestMode) {
        Write-Host "Test mode completed: no suspicious parent/child relationship detected."
    }
    else {
        Write-Host "No suspicious Office parent/child process activity detected in the last $LookbackMinutes minutes."
    }
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
    if ($TestMode) {
        Write-Host "ValidationMode: Synthetic"
    }
    Write-Host ""
}
