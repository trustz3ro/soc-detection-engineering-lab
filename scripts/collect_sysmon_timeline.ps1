param(
    [int]$LookbackMinutes = 10,
    [string]$ProcessGuid = ""
)

$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)
$logName = 'Microsoft-Windows-Sysmon/Operational'

function Convert-SysmonEvent {
    param($Event)

    [xml]$xml = $Event.ToXml()
    $data = @{}

    foreach ($node in $xml.Event.EventData.Data) {
        $data[$node.Name] = [string]$node.'#text'
    }

    [pscustomobject]@{
        TimeCreated       = $Event.TimeCreated
        EventId           = $Event.Id
        ProcessGuid       = $data['ProcessGuid']
        ProcessId         = $data['ProcessId']
        Image             = $data['Image']
        CommandLine       = $data['CommandLine']
        ParentImage       = $data['ParentImage']
        ParentCommandLine = $data['ParentCommandLine']
        User              = $data['User']
        QueryName         = $data['QueryName']
        QueryResults      = $data['QueryResults']
        SourceIp          = $data['SourceIp']
        SourcePort        = $data['SourcePort']
        DestinationIp     = $data['DestinationIp']
        DestinationPort   = $data['DestinationPort']
        Protocol          = $data['Protocol']
    }
}

$events = Get-WinEvent -FilterHashtable @{
    LogName   = $logName
    Id        = 1,3,22
    StartTime = $startTime
}

$records = foreach ($event in $events) {
    Convert-SysmonEvent -Event $event
}

if ($ProcessGuid) {
    $records = $records | Where-Object {
        $_.ProcessGuid -eq $ProcessGuid
    }
}

if (-not $records) {
    Write-Host "No matching Sysmon events found."
    exit
}

$records |
    Sort-Object TimeCreated |
    Format-Table TimeCreated, EventId, ProcessId, Image, QueryName, DestinationIp, DestinationPort -AutoSize

Write-Host ""
Write-Host "Detailed timeline:"
Write-Host ""

foreach ($record in ($records | Sort-Object TimeCreated)) {
    Write-Host "Time: $($record.TimeCreated)"
    Write-Host "EventId: $($record.EventId)"
    Write-Host "ProcessGuid: $($record.ProcessGuid)"
    Write-Host "ProcessId: $($record.ProcessId)"
    Write-Host "Image: $($record.Image)"

    if ($record.CommandLine) {
        Write-Host "CommandLine: $($record.CommandLine)"
    }

    if ($record.ParentImage) {
        Write-Host "ParentImage: $($record.ParentImage)"
    }

    if ($record.ParentCommandLine) {
        Write-Host "ParentCommandLine: $($record.ParentCommandLine)"
    }

    if ($record.User) {
        Write-Host "User: $($record.User)"
    }

    if ($record.QueryName) {
        Write-Host "QueryName: $($record.QueryName)"
        Write-Host "QueryResults: $($record.QueryResults)"
    }

    if ($record.DestinationIp) {
        Write-Host "Protocol: $($record.Protocol)"
        Write-Host "SourceIp: $($record.SourceIp)"
        Write-Host "SourcePort: $($record.SourcePort)"
        Write-Host "DestinationIp: $($record.DestinationIp)"
        Write-Host "DestinationPort: $($record.DestinationPort)"
    }

    Write-Host "----------------------------------------"
}
