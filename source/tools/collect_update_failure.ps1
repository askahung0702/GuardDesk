# Read fixed GuardDesk metadata only. No config, command line, document or network access.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{24}$')][string]$DeviceId,
    [string]$OutputPath=(Join-Path $PSScriptRoot 'GuardDesk-Update-Failure.json'),
    [string]$ProgramRoot=(Join-Path $env:ProgramFiles 'GuardDeskPilot'),
    [string]$DataRoot=(Join-Path $env:ProgramData 'GuardDeskPilot')
)
$ErrorActionPreference='Stop'
function Assert-Plain([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while($current) {
        if([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            if(([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw [IO.IOException]::new('Reparse path rejected')}
        }
        $parent=[IO.Path]::GetDirectoryName($current)
        if($parent -eq $current){break}
        $current=$parent
    }
}
function Safe-Failure($Value) {
    $out=[ordered]@{}
    if($Value.stage -in @('stopping','switching','restarting','health','unknown')){$out.stage=$Value.stage}
    if($Value.type -in @('OSError','PermissionError','FileNotFoundError','FileExistsError','TimeoutError','TimeoutExpired','ValueError','ConnectionError','Exception')){$out.type=$Value.type}
    foreach($name in @('winerror','errno')) {
        $v=$Value.$name
        if(($v -is [int] -or $v -is [long]) -and $v -ge 0 -and $v -le 65535){$out[$name]=$v}
    }
    return $out
}
function Read-Metadata([string]$Path,[string]$Kind) {
    try {
        Assert-Plain $Path
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            if($stream.Length -gt 2097152){return @{status='too_large'}}
            # Fixed maximum read even if another process grows the metadata file.
            $bytes=New-Object byte[] 2097153
            $count=0
            while($count -lt $bytes.Length) {
                $got=$stream.Read($bytes,$count,$bytes.Length-$count)
                if($got -eq 0){break}
                $count+=$got
            }
            if($count -gt 2097152){return @{status='too_large'}}
            $text=[Text.Encoding]::UTF8.GetString($bytes,0,$count).TrimStart([char]0xfeff)
        } finally {$stream.Dispose()}
        $v=ConvertFrom-Json -InputObject $text
        if($null -eq $v -or $v -is [array] -or $v -is [string]){return @{status='invalid_object'}}
        $out=[ordered]@{status='read';modified_utc=([IO.File]::GetLastWriteTimeUtc($Path).ToString('o'))}
        foreach($name in @('version','native_version','old_version','target')) {
            $s=$v.$name
            if($s -is [string] -and $s -cmatch '^\d{1,4}\.\d{1,4}\.\d{1,4}$'){$out[$name]=$s}
        }
        if($Kind -eq 'transaction') {
            if($v.phase -in @('downloading','prepared','stopping','switching','old_moved','restarting','starting','healthy','rolled_back','failed')){$out.phase=$v.phase}
            if($v.reported -is [bool]){$out.reported=$v.reported}
            if($null -ne $v.failure){$out.failure=Safe-Failure $v.failure}
            if($null -ne $v.rollback_failure){$out.rollback_failure=Safe-Failure $v.rollback_failure}
            $jid=$v.job.id
            if($null -eq $jid){$jid=$v.job_id}
            if($jid -is [string] -and $jid -cmatch '^[0-9a-f]{32}$'){$out.job_id=$jid}
        }
        if($Kind -eq 'broker_status') {
            if($v.code -in @('initialization_failed','recovery_failed','transport_failed','execution_failed')){$out.code=$v.code}
            if($v.error_type -in @('OSError','PermissionError','FileNotFoundError','FileExistsError','TimeoutError','TimeoutExpired','ValueError','ConnectionError','KeyError','JSONDecodeError')){$out.error_type=$v.error_type}
        }
        if($Kind -ne 'manifest') {
            foreach($name in @('time','started')) {
                $n=$v.$name
                if(($n -is [int] -or $n -is [long] -or $n -is [double]) -and $n -ge 0 -and $n -le 4102444800){$out[$name]=$n}
            }
            if(($v.pid -is [int] -or $v.pid -is [long]) -and $v.pid -gt 0 -and $v.pid -le 4294967295){$out.pid=$v.pid}
        }
        return $out
    } catch {
        $e=$_.Exception
        while($null -ne $e.InnerException){$e=$e.InnerException}
        return @{status='read_error';error_type=$e.GetType().Name;hresult=$e.HResult}
    }
}
$ProgramRoot=[IO.Path]::GetFullPath($ProgramRoot)
$DataRoot=[IO.Path]::GetFullPath($DataRoot)
$private=Join-Path $DataRoot ('USBControl\'+$DeviceId)
$updates=Join-Path $private 'updates'
$report=[ordered]@{
    format=1;device_id=$DeviceId;observed_utc=[DateTime]::UtcNow.ToString('o');read_only=$true
    metadata=[ordered]@{}
}
$spec=@(
    @('broker_health',(Join-Path $private 'broker-health.json'),'health'),
    @('native_health',(Join-Path $private 'native-health.json'),'health'),
    @('broker_status',(Join-Path $private 'update-broker-status.json'),'broker_status'),
    @('native_transaction',(Join-Path $updates 'transaction-native.json'),'transaction'),
    @('updater_refresh',(Join-Path $updates 'updater-refresh.json'),'transaction'),
    @('updater_manifest',(Join-Path $ProgramRoot 'Updater\_internal\agent-release.json'),'manifest'),
    @('native_manifest',(Join-Path $ProgramRoot 'USBControl\_internal\agent-release.json'),'manifest')
)
foreach($s in $spec){$report.metadata[$s[0]]=Read-Metadata $s[1] $s[2]}
# Bounded directory names and package lengths only; no recursive program/cache scan.
$report.cache=[ordered]@{packages=@();truncated=$false;status='read'}
try {
    Assert-Plain $updates
    $iterator=[IO.Directory]::EnumerateDirectories($updates).GetEnumerator()
    try {
        $seen=0
        while($iterator.MoveNext()) {
            $seen++
            if($seen -gt 64){$report.cache.truncated=$true;break}
            $dir=$iterator.Current;$name=[IO.Path]::GetFileName($dir)
            if($name -cnotmatch '^[0-9a-f]{32}$'){continue}
            $row=[ordered]@{job_id=$name}
            foreach($file in @('package.zip','package.part')) {
                $p=Join-Path $dir $file
                try {Assert-Plain $p;if([IO.File]::Exists($p)){$row[$file]=([IO.FileInfo]::new($p)).Length}}
                catch {$row.status='path_unreadable_or_reparse'}
            }
            $report.cache.packages+=@($row)
        }
    } finally {if($iterator -is [IDisposable]){$iterator.Dispose()}}
} catch {$report.cache.status='unreadable_or_missing'}
$report.program_directories=@()
try {
    Assert-Plain $ProgramRoot
    $iterator=[IO.Directory]::EnumerateDirectories($ProgramRoot).GetEnumerator()
    try {
        $seen=0
        while($iterator.MoveNext()) {
            $seen++;if($seen -gt 64){break}
            $name=[IO.Path]::GetFileName($iterator.Current)
            if($name -cmatch '^(USBControl|Updater)(\.(stage|rollback|failed)-[0-9a-f]{32})?$'){$report.program_directories+=@($name)}
        }
    } finally {if($iterator -is [IDisposable]){$iterator.Dispose()}}
} catch {$report.program_inventory_status='unreadable_or_missing'}
$report.note='Metadata snapshot only. Does not prove current lock owner, full cache size, package integrity, successful install or Defender acceptance. No raw config, exception text, job envelope or file content copied.'
$OutputPath=[IO.Path]::GetFullPath($OutputPath)
Assert-Plain $OutputPath
foreach($root in @($DataRoot,$ProgramRoot)) {
    if($OutputPath.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $OutputPath.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Report output must be outside installation/data roots'}
}
if([IO.File]::Exists($OutputPath) -or [IO.Directory]::Exists($OutputPath)){throw 'Report already exists. Keep the previous report and select a new OutputPath.'}
$json=ConvertTo-Json -InputObject $report -Depth 10
$output=[IO.File]::Open($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json)
    $output.Write($bytes,0,$bytes.Length)
} finally {$output.Dispose()}
Write-Output $json
