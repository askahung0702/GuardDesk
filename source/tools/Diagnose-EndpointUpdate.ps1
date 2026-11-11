# Read-only local MIS diagnostic. No config/token/manifest/command line collection.
$ErrorActionPreference='Stop'

function Read-UpdateFields([string]$Path,[string[]]$Fields) {
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return @{available=$false}}
    try {
        $entry=Get-Item -LiteralPath $Path -Force
        if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){return @{available=$false;reason='reparse_rejected'}}
        if($entry.Length -gt 1048576){return @{available=$false;reason='size_limit'}}
        $body=Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        $result=@{available=$true}
        foreach($field in $Fields){
            $property=$body.PSObject.Properties[$field]
            if($null -eq $property){continue}
            $value=$property.Value
            if($value -is [string]){if($value.Length -le 250){$result[$field]=$value}}
            elseif($value -is [ValueType] -or $null -eq $value){$result[$field]=$value}
        }
        return $result
    } catch {return @{available=$false;reason=$_.Exception.GetType().Name}}
}

function Invoke-UpdateDiagnostic {
    $identity=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $report=[ordered]@{format=1;tool='GuardDesk-Update-Diagnostic';read_only=$true;computer=$env:COMPUTERNAME;time_utc=[DateTime]::UtcNow.ToString('o');administrator=$identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);tasks=@();native_records=@();application_crashes=@();notes=@()}
    try {
        $os=Get-CimInstance Win32_OperatingSystem
        $report.os=@{caption=$os.Caption;version=$os.Version;architecture=$os.OSArchitecture}
    } catch {$report.notes+='OS query unavailable'}
    try {
        $tasks=@(Get-ScheduledTask -TaskName 'GuardDesk-*' -ErrorAction Stop | Where-Object {$_.TaskName -match '^GuardDesk-(USBControl|AgentUpdater)-[0-9a-f]{24}$'} | Select-Object -First 16)
        foreach($task in $tasks){
            try {
                $info=Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
                $report.tasks+=@{name=$task.TaskName;state=[string]$task.State;last_result=('0x{0:X8}' -f [uint32]$info.LastTaskResult);last_run=$info.LastRunTime.ToString('o');missed=$info.NumberOfMissedRuns}
            } catch {$report.tasks+=@{name=$task.TaskName;reason=$_.Exception.GetType().Name}}
        }
    } catch {$report.notes+='Scheduled-task query unavailable or no matching task'}
    $dataRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'GuardDeskPilot\USBControl'
    try {
        $folders=@(Get-ChildItem -LiteralPath $dataRoot -Directory -ErrorAction Stop | Where-Object {$_.Name -match '^[0-9a-f]{24}$' -and ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0} | Select-Object -First 8)
        foreach($folder in $folders){
            $report.native_records+=@{device_id=$folder.Name;
                transaction=(Read-UpdateFields (Join-Path $folder.FullName 'updates\transaction-native.json') @('phase','old_version','target','version','error','started','reported'));
                health=(Read-UpdateFields (Join-Path $folder.FullName 'native-health.json') @('version','time','pid'));
                broker_health=(Read-UpdateFields (Join-Path $folder.FullName 'broker-health.json') @('version','native_version','time','pid'));
                broker_status=(Read-UpdateFields (Join-Path $folder.FullName 'update-broker-status.json') @('state','code','error_type','time'))}
        }
    } catch {$report.notes+='Protected native metadata unavailable; MIS may need an administrator session'}
    try {
        $records=Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000;StartTime=(Get-Date).AddDays(-3)} -MaxEvents 128 -ErrorAction Stop
        foreach($record in $records){
            $raw=$record.ToXml();if($raw.Length -gt 32768){continue};$xml=[xml]$raw;$values=@{}
            foreach($item in $xml.Event.EventData.Data){if($item.Name){$values[[string]$item.Name]=[string]$item.'#text'}}
            $app=$values['AppName'];if(-not $app){$app=$values['FaultingApplicationName']}
            if($app -notin @('GuardDesk.exe','GuardDeskAgent.exe')){continue}
            $report.application_crashes+=@{time=$record.TimeCreated.ToString('o');event_id=$record.Id;record_id=$record.RecordId;application=$app;application_version=$values['AppVersion'];module=$values['ModuleName'];exception_code=$values['ExceptionCode']}
            if($report.application_crashes.Count -ge 8){break}
        }
    } catch {$report.notes+='No readable matching Application Error records; absence does not prove the worker was healthy'}
    $report.notes+='No installer/update/task/registry/policy operation was executed. Native SQLite content and Defender/security logs were not collected.'
    $json=$report | ConvertTo-Json -Depth 8
    $output=Join-Path $PSScriptRoot 'GuardDesk-Update-Diagnostic.json'
    if(Test-Path -LiteralPath $output){
        $entry=Get-Item -LiteralPath $output -Force
        if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $entry.PSIsContainer){throw 'Diagnostic output must be a normal local file.'}
    }
    [IO.File]::WriteAllText($output,$json,[Text.UTF8Encoding]::new($true))
    Write-Host ('Saved: '+$output)
    Write-Host 'Send only GuardDesk-Update-Diagnostic.json to MIS/support. Do not send config.json or private keys.'
}

if($MyInvocation.InvocationName -ne '.') {Invoke-UpdateDiagnostic}
