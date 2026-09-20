param(
    [int]$LookbackMinutes = 30
)

$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)

Write-Host "=== Current Local Administrators Group ==="
try {
    Get-LocalGroupMember -Group "Administrators" |
        Select-Object Name, ObjectClass, PrincipalSource |
        Format-Table -AutoSize
}
catch {
    Write-Host "Unable to enumerate local Administrators group: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "=== Recent Security Event ID 4732 ==="

$groupEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4732
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $groupEvents) {
    Write-Host "No Event ID 4732 records found in the last $LookbackMinutes minutes."
}
else {
    foreach ($event in $groupEvents) {
        [xml]$xml = $event.ToXml()
        $data = @{}

        foreach ($node in $xml.Event.EventData.Data) {
            $data[$node.Name] = [string]$node.'#text'
        }

        Write-Host "Time: $($event.TimeCreated)"
        Write-Host "Actor: $($data['SubjectDomainName'])\$($data['SubjectUserName'])"
        Write-Host "MemberName: $($data['MemberName'])"
        Write-Host "MemberSid: $($data['MemberSid'])"
        Write-Host "TargetGroup: $($data['TargetDomainName'])\$($data['TargetUserName'])"
        Write-Host "----------------------------------------"
    }
}

Write-Host ""
Write-Host "=== Recent Successful / Failed Logons ==="

$logonEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624,4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue |
    Select-Object -First 25

if (-not $logonEvents) {
    Write-Host "No Event ID 4624 or 4625 records found in the last $LookbackMinutes minutes."
}
else {
    foreach ($event in $logonEvents) {
        [xml]$xml = $event.ToXml()
        $data = @{}

        foreach ($node in $xml.Event.EventData.Data) {
            $data[$node.Name] = [string]$node.'#text'
        }

        Write-Host "Time: $($event.TimeCreated)"
        Write-Host "EventId: $($event.Id)"
        Write-Host "TargetUser: $($data['TargetDomainName'])\$($data['TargetUserName'])"
        Write-Host "LogonType: $($data['LogonType'])"
        Write-Host "IpAddress: $($data['IpAddress'])"
        Write-Host "ProcessName: $($data['ProcessName'])"
        Write-Host "----------------------------------------"
    }
}
