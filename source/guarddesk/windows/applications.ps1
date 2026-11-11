param([ValidateSet('Configure','Restore')][string]$Action)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json
$root=[IO.Path]::GetFullPath([string]$payload.state_dir)
if(-not([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required'}
New-Item -ItemType Directory -Path $root -Force|Out-Null
function Save-Json($value,$path){[IO.File]::WriteAllText($path,($value|ConvertTo-Json -Depth 10 -Compress),[Text.UTF8Encoding]::new($false))}
function Hash-Text([string]$text){$sha=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-','')}finally{$sha.Dispose()}}
$original=Join-Path $root 'applocker-original.xml'
$managed=Join-Path $root 'applocker-managed.json'
$serviceBackup=Join-Path $root 'appidsvc-original.json'
function Restore-AppLocker {
    if(Test-Path -LiteralPath $managed){
        Import-Module AppLocker -ErrorAction Stop
        $last=Get-Content -LiteralPath $managed -Raw|ConvertFrom-Json
        $current=[string](Get-AppLockerPolicy -Local -Xml)
        if((Hash-Text $current) -ne $last.hash){throw 'AppLocker changed outside GuardDesk; preserve company policy'}
        Set-AppLockerPolicy -XmlPolicy $original -ErrorAction Stop
        Remove-Item -LiteralPath $managed -Force
    }
    if(Test-Path -LiteralPath $serviceBackup){
        $savedService=Get-Content -LiteralPath $serviceBackup -Raw|ConvertFrom-Json
        $serviceInfo=Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
        if($serviceInfo.StartMode -ne 'Auto'){throw 'AppIDSvc startup changed outside GuardDesk; preserve company setting'}
        $mode=@{Auto='Automatic';Manual='Manual';Disabled='Disabled'}[[string]$savedService.start_mode]
        Set-Service -Name AppIDSvc -StartupType $mode -ErrorAction Stop
        if($savedService.state -ne 'Running'){Stop-Service -Name AppIDSvc -ErrorAction Stop}
        Remove-Item -LiteralPath $serviceBackup -Force
    }
}
$auditBackup=Join-Path $root 'process-audit-original.json'
$auditCsv=Join-Path $root 'process-audit.csv'
$ids=@('{0CCE922B-69AE-11D9-BED3-505054503030}','{0CCE922C-69AE-11D9-BED3-505054503030}')
function Audit-Flags {
    & (Join-Path ([Environment]::SystemDirectory) 'auditpol.exe') /backup "/file:$auditCsv" | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Process audit backup failed'}
    $values=@{}
    foreach($id in $ids){$line=Get-Content -LiteralPath $auditCsv | Where-Object {$_ -match [regex]::Escape($id)} | Select-Object -First 1;if(-not $line){throw 'Missing process audit subcategory'};$values[$id]=[int](($line -split ',')[-1].Trim('"'))}
    return $values
}
function Restore-ProcessAudit {
    if(Test-Path -LiteralPath $auditBackup){
        $saved=Get-Content -LiteralPath $auditBackup -Raw|ConvertFrom-Json;$current=Audit-Flags
        foreach($id in $ids){$flags=[int]$saved.$id;if($current[$id] -ne ($flags -bor 1)){throw 'Process audit changed outside GuardDesk; preserve company policy'}}
        foreach($id in $ids){$flags=[int]$saved.$id;$success=if($flags -band 1){'enable'}else{'disable'};$failure=if($flags -band 2){'enable'}else{'disable'};& (Join-Path ([Environment]::SystemDirectory) 'auditpol.exe') /set "/subcategory:$id" "/success:$success" "/failure:$failure"|Out-Null;if($LASTEXITCODE -ne 0){throw 'Process audit restore failed'}}
        Remove-Item -LiteralPath $auditBackup -Force
    }
}
if($Action -eq 'Restore'){Restore-AppLocker;Restore-ProcessAudit;@{status='restored'}|ConvertTo-Json -Compress;exit}
if(-not $payload.PSObject.Properties['manage_audit'] -or $payload.manage_audit){
if($payload.audit){
    $current=Audit-Flags
    if(-not(Test-Path -LiteralPath $auditBackup)){Save-Json $current $auditBackup}
    $saved=Get-Content -LiteralPath $auditBackup -Raw|ConvertFrom-Json
    foreach($id in $ids){if($current[$id] -notin @([int]$saved.$id,([int]$saved.$id -bor 1))){throw 'Process audit conflict'};& (Join-Path ([Environment]::SystemDirectory) 'auditpol.exe') /set "/subcategory:$id" /success:enable | Out-Null;if($LASTEXITCODE -ne 0){throw 'Process audit enable failed'}}
}else{Restore-ProcessAudit}
}
$control='disabled'
if($payload.enabled){
    Import-Module AppLocker -ErrorAction Stop
    $current=[string](Get-AppLockerPolicy -Local -Xml)
    if(Test-Path -LiteralPath $managed){$last=Get-Content -LiteralPath $managed -Raw|ConvertFrom-Json;if((Hash-Text $current) -ne $last.hash){throw 'AppLocker policy conflict'}}
    else{
        [xml]$local=$current;[xml]$effective=Get-AppLockerPolicy -Effective -Xml
        if(@($local.SelectNodes('//RuleCollection/*')).Count -or @($effective.SelectNodes('//RuleCollection/*')).Count){throw 'Existing company AppLocker rules detected; use MIS policy merge review, no overwrite'}
        [IO.File]::WriteAllText($original,$current,[Text.UTF8Encoding]::new($false))
    }
    $policyPath=Join-Path $root 'candidate.xml';[IO.File]::WriteAllText($policyPath,[string]$payload.xml,[Text.UTF8Encoding]::new($false))
    # Never enable a policy that denies this protected worker.
    $self=Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'GuardDesk.exe'
    $safePaths=@($self,(Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'),(Join-Path ([Environment]::GetFolderPath('Windows')) 'explorer.exe'))
    foreach($name in @('auditpol.exe','lsass.exe','svchost.exe','services.exe','winlogon.exe','csrss.exe','smss.exe','wininit.exe','LogonUI.exe')){$safePaths+=Join-Path ([Environment]::SystemDirectory) $name}
    $safePaths=@($safePaths | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf})
    # SYSTEM can be exempt from ordinary AppLocker evaluation. Independently
    # reject denials matching protected files even when no employee is logged in.
    [xml]$candidate=[string]$payload.xml
    $denyHashes=@($candidate.SelectNodes('//FileHashRule[@Action="Deny"]/Conditions/FileHashCondition/FileHash') | ForEach-Object {[string]$_.Data})
    $denyPaths=@($candidate.SelectNodes('//FilePathRule[@Action="Deny"]/Conditions/FilePathCondition') | ForEach-Object {[string]$_.Path})
    foreach($safePath in $safePaths){
        foreach($denyPath in $denyPaths){if($safePath -like $denyPath){throw 'Candidate denies a protected maintenance path'}}
        if($denyHashes.Count){$safeInfo=Get-AppLockerFileInformation -Path $safePath -ErrorAction Stop;if($denyHashes -contains $safeInfo.Hash.HashDataString){throw 'Candidate denies a protected maintenance file hash'}}
        $publisherRules=@($candidate.SelectNodes('//FilePublisherRule[@Action="Deny"]/Conditions/FilePublisherCondition'))
        if($publisherRules.Count){
            $safeInfo=Get-AppLockerFileInformation -Path $safePath -ErrorAction Stop
            if($safeInfo.Publisher){
                foreach($rule in $publisherRules){
                    $p=$safeInfo.Publisher
                    if(([string]$p.PublisherName -like [string]$rule.PublisherName) -and ([string]$p.ProductName -like [string]$rule.ProductName) -and ([string]$p.BinaryName -like [string]$rule.BinaryName)){
                        $low=[string]$rule.BinaryVersionRange.LowSection;$high=[string]$rule.BinaryVersionRange.HighSection
                        if(([version]$p.BinaryVersion -ge [version]$low) -and ($high -eq '*' -or [version]$p.BinaryVersion -le [version]$high)){throw 'Candidate denies a protected maintenance publisher'}
                    }
                }
            }
        }
    }
    $test=@(Test-AppLockerPolicy -XmlPolicy $policyPath -Path $safePaths -User 'S-1-5-18' -ErrorAction Stop)
    $test+=Test-AppLockerPolicy -XmlPolicy $policyPath -Path $safePaths -User ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -ErrorAction Stop
    if(@($test | Where-Object {$_.PolicyDecision -notin @('Allowed','AllowedByDefault')}).Count){throw 'Candidate would block GuardDesk worker'}
    $service=Get-Service -Name AppIDSvc -ErrorAction Stop
    if(-not(Test-Path -LiteralPath $serviceBackup)){
        $serviceInfo=Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
        Save-Json @{start_mode=$serviceInfo.StartMode;state=$serviceInfo.State} $serviceBackup
    }
    Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop
    if($service.Status -ne 'Running'){Start-Service -Name AppIDSvc -ErrorAction Stop}
    Set-AppLockerPolicy -XmlPolicy $policyPath -ErrorAction Stop
    $applied=[string](Get-AppLockerPolicy -Local -Xml)
    Save-Json @{hash=(Hash-Text $applied)} $managed
    $control='configured_requires_execution_test'
}else{Restore-AppLocker}
@{status='configured';application_control=$control;process_audit_enabled=[bool]$payload.audit;scope='AppLocker Exe and Windows Installer; no Store or script blanket block'}|ConvertTo-Json -Compress
