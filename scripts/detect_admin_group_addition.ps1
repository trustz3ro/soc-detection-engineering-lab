param(
    [int]$LookbackMinutes = 30,
    [switch]$TestMode
)

$records = @()

if ($TestMode) {
    $records += [pscustomobject]@{
        TimeCreated       = Get-Date
        EventId           = 4732
        SubjectUserName   = 'ej975'
        SubjectDomainName = 'Ed_T14'
        MemberName        = 'LAB\\testuser'
        MemberSid         = 'S-1-5-21-111111111-222222222-333333333-1001'
        TargetUserName    = 'Administrators'
        TargetDomainName  = 'Builtin'
        Computer          = 'ED_T14'
        ValidationMode    = 'Synthetic'
    }
}
else {
    $startTime = (Get-Date).AddMinutes(-$LookbackMinutes)

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4732
        StartTime = $startTime
    } -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $data = @{}

        foreach ($node in $xml.Event.EventData.Data) {
            $data[$node.Name] = [string]$node.'#text'
        }

        $records += [pscustomobject]@{
            TimeCreated       = $event.TimeCreated
            EventId           = $event.Id
            SubjectUserName   = $data['SubjectUserName']
            SubjectDomainName = $data['SubjectDomainName']
            MemberName        = $data['MemberName']
            MemberSid         = $data['MemberSid']
            TargetUserName    = $data['TargetUserName']
            TargetDomainName  = $data['TargetDomainName']
            Computer          = $event.MachineName
            ValidationMode    = 'Live'
        }
    }
}

$alerts = @()

foreach ($record in $records) {
    if ($record.EventId -eq 4732 -and $record.TargetUserName -match '(?i)^Administrators$') {
        $alerts += $record
    }
}

if ($alerts.Count -eq 0) {
    if ($TestMode) {
        Write-Host "Test mode completed: no privileged local group membership change detected."
    }
    else {
        Write-Host "No additions to the local Administrators group detected in the last $LookbackMinutes minutes."
    }
    exit
}

foreach ($alert in ($alerts | Sort-Object TimeCreated -Descending)) {
    Write-Host "ALERT: Account added to privileged local group."
    Write-Host "Time: $($alert.TimeCreated)"
    Write-Host "EventId: $($alert.EventId)"
    Write-Host "Computer: $($alert.Computer)"
    Write-Host "Actor: $($alert.SubjectDomainName)\\$($alert.SubjectUserName)"
    Write-Host "MemberName: $($alert.MemberName)"
    Write-Host "MemberSid: $($alert.MemberSid)"
    Write-Host "TargetGroup: $($alert.TargetDomainName)\\$($alert.TargetUserName)"
    Write-Host "ValidationMode: $($alert.ValidationMode)"
    Write-Host ""
}
