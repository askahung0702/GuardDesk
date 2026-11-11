param(
    [ValidateSet('Install','Uninstall','Status')][string]$Action='Install',
    [Parameter(Mandatory=$true)][string]$SourceDirectory,
    [Parameter(Mandatory=$true)][string]$SourceConfig
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$admin=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $admin){throw 'Administrator required; double-click Setup-Endpoint.cmd to request UAC.'}
function Assert-NoReparse([string]$path){
    $current=[IO.Path]::GetFullPath($path)
    while($current){
        if(Test-Path -LiteralPath $current){if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw ('拒絕 reparse/junction 路徑：'+$current)}}
        $parent=[IO.Path]::GetDirectoryName($current)
        if($parent -eq $current){break};$current=$parent
    }
}
function Protect-Directory([string]$path){
    Assert-NoReparse $path
    if(Test-Path -LiteralPath $path){
        $existing=Get-Acl -LiteralPath $path
        $owner=$existing.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw ('拒絕採用非管理員擁有的安裝目錄：'+$path)}
        foreach($entry in $existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
            $write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
            if($entry.AccessControlType -eq 'Allow' -and ($entry.FileSystemRights -band $write) -and $entry.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw ('安裝目錄可由一般使用者改寫：'+$path)}
        }
    }
    $security=[Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true,$false)
    $admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security.SetOwner($admins)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){
        $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    # Suppress implicit owner WRITE_DAC on files created by an elevated user.
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-3-4'),[Security.AccessControl.FileSystemRights]::ReadPermissions,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    if(-not(Test-Path -LiteralPath $path)){[IO.Directory]::CreateDirectory($path,$security)|Out-Null}
    Set-Acl -LiteralPath $path -AclObject $security
}
function Save-Json($value,[string]$path){[IO.File]::WriteAllText($path,(ConvertTo-Json -InputObject $value -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))}
function Assert-TrustedTree([string]$path){
    foreach($item in @(Get-ChildItem -LiteralPath $path -Recurse -Force)){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw '拒絕採用包含 reparse point 的安裝目錄'}
        $acl=Get-Acl -LiteralPath $item.FullName
        if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw ('既有安裝檔案擁有者不受信任：'+$item.FullName)}
        foreach($entry in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
            $write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
            if($entry.AccessControlType -eq 'Allow' -and ($entry.FileSystemRights -band $write) -and $entry.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw ('既有程式檔可由一般使用者改寫：'+$item.FullName)}
        }
    }
}
function Get-InstalledWorkers([string]$exe){
    @(Get-CimInstance Win32_Process -Filter "Name='GuardDesk.exe'" -ErrorAction Stop | Where-Object {
        $_.ExecutablePath -and [IO.Path]::GetFullPath($_.ExecutablePath) -ieq $exe
    })
}
function Stop-InstalledWorker([string]$exe,[string]$configPath,[int]$graceSeconds=5,[ValidateSet('usb-worker','update-service')][string]$verb='usb-worker'){
    # Stopping the task can leave the PyInstaller child alive. Give it time to
    # exit, then stop only this protected binary with this exact worker config.
    $deadline=[DateTime]::UtcNow.AddSeconds($graceSeconds)
    do {
        $running=@(Get-InstalledWorkers $exe)
        if(-not $running.Count){return}
        Start-Sleep -Milliseconds 250
    } while([DateTime]::UtcNow -lt $deadline)
    $configArgument='(?i)(?:^|\s)--config\s+"?'+[regex]::Escape($configPath)+'"?(?:\s|$)'
    foreach($process in $running){
        if($process.CommandLine -notmatch ('(?i)(?:^|\s)'+[regex]::Escape($verb)+'(?:\s|$)') -or $process.CommandLine -notmatch $configArgument){
            throw ('Another process uses the installed binary; preserve it and review PID '+$process.ProcessId)
        }
    }
    foreach($process in $running){
        # Recheck PID identity immediately before terminating a leftover child.
        $current=Get-CimInstance Win32_Process -Filter ('ProcessId='+$process.ProcessId) -ErrorAction Stop
        if($current -and $current.CreationDate -eq $process.CreationDate -and $current.ExecutablePath -ieq $exe -and $current.CommandLine -eq $process.CommandLine){
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
    $deadline=[DateTime]::UtcNow.AddSeconds(5)
    while(@(Get-InstalledWorkers $exe).Count){
        if([DateTime]::UtcNow -ge $deadline){throw 'The installed GuardDesk worker did not stop; update aborted.'}
        Start-Sleep -Milliseconds 250
    }
}
Write-Output 'GUARDDESK_STAGE=validate_existing'
function Wait-WorkerHealth([string]$path,[string]$expected,[string]$exe,[long]$started){
    $deadline=[DateTime]::UtcNow.AddSeconds(45)
    do {
        if(Test-Path -LiteralPath $path){
            Assert-NoReparse $path
            if((Get-Item -LiteralPath $path).Length -gt 4096){throw '元件健康回報過大'}
            try {
                $health=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
                if($health.version -eq $expected -and [double]$health.time -ge $started){
                    $owned=@(Get-InstalledWorkers $exe | Where-Object {$_.ProcessId -eq $health.pid})
                    if($owned.Count){return}
                }
            } catch [System.ArgumentException] { }
        }
        Start-Sleep -Milliseconds 250
    } while([DateTime]::UtcNow -lt $deadline)
    throw ('元件未在 45 秒內確認啟動：'+[IO.Path]::GetFileName($path)+'；保留原註冊，請 MIS 查看安裝診斷。')
}
$SourceDirectory=[IO.Path]::GetFullPath($SourceDirectory)
$SourceConfig=[IO.Path]::GetFullPath($SourceConfig)
Assert-NoReparse $SourceDirectory;Assert-NoReparse $SourceConfig
$config=Get-Content -LiteralPath $SourceConfig -Raw -Encoding UTF8 | ConvertFrom-Json
if($config.device_id -notmatch '^[0-9a-f]{24}$'){throw '端點識別碼不正確'}
$taskName='GuardDesk-USBControl-'+$config.device_id
$programParent=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'GuardDeskPilot'
$dataParent=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'GuardDeskPilot'
$programRoot=Join-Path $programParent 'USBControl'
$dataRoot=Join-Path (Join-Path $dataParent 'USBControl') $config.device_id
$protectedConfig=Join-Path $dataRoot 'config.json'
$executable=Join-Path $programRoot 'GuardDesk.exe'
$updaterRoot=Join-Path $programParent 'Updater'
$updaterExe=Join-Path $updaterRoot 'GuardDesk.exe'
$updaterName='GuardDesk-AgentUpdater-'+$config.device_id
$updaterTask=Get-ScheduledTask -TaskName $updaterName -ErrorAction SilentlyContinue
if($updaterTask){
    if(@($updaterTask.Actions).Count -ne 1 -or [IO.Path]::GetFullPath($updaterTask.Actions[0].Execute) -ine $updaterExe -or $updaterTask.Actions[0].Arguments -ine ('update-service --config "'+$protectedConfig+'"')){throw '同名更新工作不屬於本端點，保留原工作。'}
}
if($Action -in @('Install','Uninstall') -and (Test-Path -LiteralPath $protectedConfig)){
    $prior=Get-Content -LiteralPath $protectedConfig -Raw -Encoding UTF8|ConvertFrom-Json
    if($Action -eq 'Install' -and $prior.PSObject.Properties['update_key'] -and $prior.update_key -and (-not $config.PSObject.Properties['update_key'] -or $prior.update_key -cne $config.update_key)){throw '更新信任金鑰變更，請 MIS 核對，不自動替換。'}
    $journal=Join-Path $dataRoot 'updates\transaction-native.json'
    if(Test-Path -LiteralPath $journal){$progress=Get-Content -LiteralPath $journal -Raw|ConvertFrom-Json;if($progress.phase -in @('stopping','switching','old_moved','restarting')){throw '原生更新尚未完成／回復，先由 MIS 處理，未覆寫。'}}
}
$task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if($Action -eq 'Install'){
    $other=@(Get-ScheduledTask -TaskName 'GuardDesk-USBControl-*' -ErrorAction SilentlyContinue | Where-Object {$_.TaskName -ne $taskName})
    if($other.Count){throw '此電腦已有其他端點識別碼的 GuardDesk 原生工作。請先由 MIS 核對並移除舊註冊，避免兩套機器策略互相覆寫。'}
}
if($task){
    if(@($task.Actions).Count -ne 1 -or [IO.Path]::GetFullPath($task.Actions[0].Execute) -ine $executable){throw '同名工作並非 GuardDesk USB 控制，保留現狀。'}
}
if($Action -eq 'Status'){
    @{task=$taskName;installed=($null -ne $task);state=$(if($task){[string]$task.State}else{'not_installed'});config=$protectedConfig;executable=$executable}|ConvertTo-Json -Compress
    exit 0
}
if($Action -eq 'Uninstall'){
    if($updaterTask){Stop-ScheduledTask -TaskName $updaterName;Stop-InstalledWorker $updaterExe $protectedConfig 5 'update-service';Unregister-ScheduledTask -TaskName $updaterName -Confirm:$false}
    if(-not $task -and -not(Test-Path -LiteralPath $protectedConfig)){Write-Output 'USB 背景工作尚未安裝';exit 0}
    if($task){Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop}
    Stop-InstalledWorker $executable $protectedConfig
    & $executable usb-worker --config $protectedConfig --extended --restore
    if($LASTEXITCODE -ne 0){throw 'USB 原有策略還原失敗；保留工作與備份，請檢查衝突。'}
    if($task){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
    Write-Output '已還原 USB 基準並移除開機工作；受保護備份保留。';exit 0
}
if(-not(Test-Path -LiteralPath (Join-Path $SourceDirectory 'GuardDesk.exe'))){throw '缺少 GuardDesk.exe'}
if(-not(Test-Path -LiteralPath (Join-Path $SourceDirectory '_internal'))){throw '缺少 _internal'}
foreach($item in @(Get-ChildItem -LiteralPath $SourceDirectory -Recurse -Force)){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw '執行包不得包含 junction／symlink。'}}
$legacy=Join-Path (Split-Path -Parent $SourceConfig) 'windows\usb-managed.json'
if(Test-Path -LiteralPath $legacy){throw '此端點已有手動 USB 控制。請先停止具管理員權限的舊 Agent 並還原舊原生控制，避免兩套控制互相覆寫。'}
Write-Output 'GUARDDESK_STAGE=protect_directories'
foreach($path in @($programParent,$programRoot,$dataParent,(Join-Path $dataParent 'USBControl'),$dataRoot)){Protect-Directory $path}
if($updaterTask){Stop-ScheduledTask -TaskName $updaterName;Stop-InstalledWorker $updaterExe $protectedConfig 5 'update-service'}
Assert-TrustedTree $programRoot;Assert-TrustedTree $dataRoot
if($task){Stop-ScheduledTask -TaskName $taskName}
$newNativeTask=$false;$newUpdaterTask=$false
try{
    Stop-InstalledWorker $executable $protectedConfig
    Write-Output 'GUARDDESK_STAGE=copy_programs'
    # SYSTEM runs only these protected copies, never files in the user workspace.
    Copy-Item -LiteralPath (Join-Path $SourceDirectory 'GuardDesk.exe') -Destination $executable -Force
    Copy-Item -LiteralPath (Join-Path $SourceDirectory '_internal') -Destination $programRoot -Recurse -Force
    $admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach($item in @(Get-ChildItem -LiteralPath $programRoot -Recurse -Force)){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw '受保護程式目錄包含 reparse point'}
        $acl=Get-Acl -LiteralPath $item.FullName;$acl.SetOwner($admins);$acl.SetAccessRuleProtection($false,$true);Set-Acl -LiteralPath $item.FullName -AclObject $acl
    }
    $unused=Join-Path $dataRoot 'unused-watch';Protect-Directory $unused
    $settings=@{server=[string]$config.server;token=[string]$config.token;device_id=[string]$config.device_id;watch=$unused;audit_watch=[string]$config.watch;ca=$null}
    if($config.PSObject.Properties['update_key'] -and $config.update_key){
        if([string]$config.update_key -notmatch '^[A-Za-z0-9+/]{43}=$'){throw '更新信任金鑰格式不正確'}
        $settings.update_key=[string]$config.update_key
        Protect-Directory $updaterRoot;Assert-TrustedTree $updaterRoot
        Copy-Item -LiteralPath (Join-Path $SourceDirectory 'GuardDesk.exe') -Destination $updaterExe -Force
        Copy-Item -LiteralPath (Join-Path $SourceDirectory '_internal') -Destination $updaterRoot -Recurse -Force
        foreach($item in @(Get-ChildItem -LiteralPath $updaterRoot -Recurse -Force)){
            $acl=Get-Acl -LiteralPath $item.FullName;$acl.SetOwner($admins);$acl.SetAccessRuleProtection($false,$true);Set-Acl -LiteralPath $item.FullName -AclObject $acl
        }
        Assert-TrustedTree $updaterRoot
    }
    if($config.PSObject.Properties['ca'] -and $config.ca){
        $ca=[string]$config.ca
        if(-not[IO.Path]::IsPathRooted($ca)){
            $base=Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $SourceConfig));$ca=Join-Path $base $ca
        }
        Assert-NoReparse $ca
        $settings.ca=Join-Path $dataRoot 'company-ca.pem';Copy-Item -LiteralPath $ca -Destination $settings.ca -Force
    }
    Write-Output 'GUARDDESK_STAGE=initial_policy'
    Save-Json $settings $protectedConfig
    & $executable usb-worker --config $protectedConfig --extended --once
    if($LASTEXITCODE -ne 0){throw '初次 USB 套用／回報未成功，未註冊新的開機工作。'}
    foreach($item in @(Get-ChildItem -LiteralPath $dataRoot -Recurse -Force)){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw '受保護資料目錄包含 reparse point'}
        $acl=Get-Acl -LiteralPath $item.FullName;$acl.SetOwner($admins);Set-Acl -LiteralPath $item.FullName -AclObject $acl
    }
    Write-Output 'GUARDDESK_STAGE=register_tasks'
    $started=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $component=(& $executable component-info | ConvertFrom-Json)
    if($LASTEXITCODE -ne 0 -or -not $component.version){throw '無法核對原生程式版本'}
    $arguments='usb-worker --extended --config "'+$protectedConfig+'"'
    $actionObject=New-ScheduledTaskAction -Execute $executable -Argument $arguments -WorkingDirectory $programRoot
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settingsObject=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -Action $actionObject -Trigger $trigger -Principal $principal -Settings $settingsObject -Description 'GuardDesk USB 與應用程式稽核／AppLocker 控制；不啟用全磁碟 SACL，不提供 SYSTEM 遠端桌面' -Force | Out-Null
    $newNativeTask=($null -eq $task)
    Start-ScheduledTask -TaskName $taskName
    if($settings.ContainsKey('update_key')){
        $updateAction=New-ScheduledTaskAction -Execute $updaterExe -Argument ('update-service --config "'+$protectedConfig+'"') -WorkingDirectory $updaterRoot
        Register-ScheduledTask -TaskName $updaterName -Action $updateAction -Trigger $trigger -Principal $principal -Settings $settingsObject -Description 'GuardDesk 明示的集中更新元件：驗證內部簽章，只更新 GuardDesk，失敗回復；不提供任意 Shell' -Force|Out-Null
        $newUpdaterTask=($null -eq $updaterTask)
        Start-ScheduledTask -TaskName $updaterName
    }
    if($settings.ContainsKey('update_key')){
        Write-Output 'GUARDDESK_STAGE=verify_workers'
        Wait-WorkerHealth (Join-Path $dataRoot 'native-health.json') $component.version $executable $started
        Wait-WorkerHealth (Join-Path $dataRoot 'broker-health.json') $component.version $updaterExe $started
    }
    Save-Json @{product='GuardDesk-USBControl';task=$taskName;config=$protectedConfig;executable=$executable;installed_at=[DateTime]::UtcNow.ToString('o')} (Join-Path $dataRoot 'installation.json')
    $manifestPath=Join-Path $dataRoot 'installation.json';$acl=Get-Acl -LiteralPath $manifestPath;$acl.SetOwner($admins);Set-Acl -LiteralPath $manifestPath -AclObject $acl
    Write-Output 'USB／應用程式背景工作已安裝。請核對收集器狀態；USB 需插拔及實測，程式管制需另外做啟動測試。'
}catch{
    $originalError=$_
    if($newUpdaterTask){Stop-ScheduledTask -TaskName $updaterName -ErrorAction SilentlyContinue;Stop-InstalledWorker $updaterExe $protectedConfig 5 'update-service';Unregister-ScheduledTask -TaskName $updaterName -Confirm:$false}
    if($newNativeTask){Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue;Stop-InstalledWorker $executable $protectedConfig;Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
    if($updaterTask){Start-ScheduledTask -TaskName $updaterName -ErrorAction SilentlyContinue}
    if($task){Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue}
    elseif(Test-Path -LiteralPath (Join-Path $dataRoot 'windows\usb-original.json')){& $executable usb-worker --config $protectedConfig --extended --restore}
    throw $originalError
}
