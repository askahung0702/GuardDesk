param([Parameter(Mandatory=$true)][ValidateSet('InstallAudit','ApplyQos','Restore')][string]$Action)
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$payload=[Console]::In.ReadToEnd() | ConvertFrom-Json
$stateDir=[IO.Path]::GetFullPath($payload.state_dir)
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
function Save-Json($value,$path) { $text=ConvertTo-Json -InputObject $value -Depth 15 -Compress; [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false)) }
function Read-Json($path,$fallback) { if(Test-Path -LiteralPath $path){ return Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json }; return $fallback }
function Enable-SecurityPrivilege {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class GuardDeskPrivilege {
 [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct TP { public uint Count; public LUID Luid; public uint Attributes; }
 [DllImport("advapi32",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr t);
 [DllImport("advapi32",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out LUID luid);
 [DllImport("advapi32",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t,bool all,ref TP state,uint len,IntPtr before,IntPtr ret);
 [DllImport("kernel32")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);
 public static void Enable() { IntPtr t; if(!OpenProcessToken(GetCurrentProcess(),0x28,out t))throw new System.ComponentModel.Win32Exception(); try { TP p=new TP();p.Count=1;p.Attributes=2;if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out p.Luid))throw new System.ComponentModel.Win32Exception();if(!AdjustTokenPrivileges(t,false,ref p,0,IntPtr.Zero,IntPtr.Zero)||Marshal.GetLastWin32Error()!=0)throw new System.ComponentModel.Win32Exception(); } finally {CloseHandle(t);} }
}
'@
    [GuardDeskPrivilege]::Enable()
}
$auditFile=Join-Path $stateDir 'sacl-backup.json'
$auditPolicy=Join-Path $stateDir 'audit-policy.csv'
$qosFile=Join-Path $stateDir 'qos-owned.json'
if($Action -eq 'ApplyQos') {
    $owned=@(Read-Json $qosFile @())
    $desired=@($payload.rules)
    $created=[Collections.Generic.List[string]]::new()
    foreach($name in $owned){ if($name){$created.Add([string]$name)} }
    $errors=[Collections.Generic.List[string]]::new()
    foreach($rule in $desired) {
        try {
            $existing=Get-NetQosPolicy -Name $rule.name -PolicyStore ActiveStore -ErrorAction SilentlyContinue
            if(-not $existing) {
                $params=@{Name=[string]$rule.name;PolicyStore='ActiveStore';NetworkProfile='All';Precedence=[uint32]$rule.precedence;ThrottleRateActionBitsPerSecond=[uint64]$rule.rate_bps;ErrorAction='Stop'}
                if($rule.app){$params.AppPathNameMatchCondition=[string]$rule.app}
                if($rule.user){$params.UserMatchCondition=[string]$rule.user}
                New-NetQosPolicy @params | Out-Null
                $created.Add([string]$rule.name)
                Save-Json @($created) $qosFile
            }
        } catch { $errors.Add($_.Exception.Message) }
    }
    # Preserve the previous protections when creating a replacement failed.
    if($errors.Count -eq 0) {
        foreach($name in $owned) {
            if($name -and $name -notin @($desired | ForEach-Object { $_.name })) {
                Remove-NetQosPolicy -Name $name -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop
            }
        }
        Save-Json @($desired | ForEach-Object { $_.name }) $qosFile
    }
    @{status=$(if($errors.Count){'failed'}elseif($desired.Count){'configured'}else{'no_rules'});rules=$desired.Count;errors=@($errors);scope='Windows_policy_based_outbound_QoS'} | ConvertTo-Json -Depth 8 -Compress
    exit
}
Enable-SecurityPrivilege
if($Action -eq 'Restore') {
    $conflicts=[Collections.Generic.List[string]]::new()
    foreach($item in @(Read-Json $auditFile @())) {
        try {
            if(-not(Test-Path -LiteralPath $item.path)){continue}
            $acl=Get-Acl -LiteralPath $item.path -Audit
            $current=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
            if($current -eq $item.before){continue}
            if($current -ne $item.after){$conflicts.Add($item.path);continue}
            $acl.SetSecurityDescriptorSddlForm($item.before,[Security.AccessControl.AccessControlSections]::Audit)
            Set-Acl -LiteralPath $item.path -AclObject $acl
        } catch { $conflicts.Add($item.path+': '+$_.Exception.Message) }
    }
    foreach($name in @(Read-Json $qosFile @())) {
        if($name){Remove-NetQosPolicy -Name $name -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue}
    }
    # Restore only this subcategory, not unrelated system audit configuration.
    $original=Read-Json (Join-Path $stateDir 'audit-original.json') $null
    if($original -and $conflicts.Count -eq 0) {
        $success=if([int]$original.flags -band 1){'enable'}else{'disable'}
        $failure=if([int]$original.flags -band 2){'enable'}else{'disable'}
        & auditpol.exe /set '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}' "/success:$success" "/failure:$failure" | Out-Null
        if($LASTEXITCODE -ne 0){throw 'auditpol restore failed'}
    }
    @{status=$(if($conflicts.Count){'conflict'}else{'restored'});conflicts=@($conflicts)} | ConvertTo-Json -Depth 5 -Compress
    exit
}
if(-not(Test-Path -LiteralPath $auditPolicy)) {
    & auditpol.exe /backup "/file:$auditPolicy" | Out-Null
    if($LASTEXITCODE -ne 0){throw 'auditpol backup failed'}
    $line=Get-Content -LiteralPath $auditPolicy | Where-Object {$_ -match '0CCE921D-69AE-11D9-BED3-505054503030'} | Select-Object -First 1
    if(-not $line){throw 'Cannot locate File System subcategory backup'}
    $flags=[int](($line -split ',')[-1].Trim('"'))
    Save-Json @{flags=$flags} (Join-Path $stateDir 'audit-original.json')
}
& auditpol.exe /set '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
if($LASTEXITCODE -ne 0){throw 'auditpol enable failed'}
$saved=[Collections.Generic.List[object]]::new()
foreach($item in @(Read-Json $auditFile @())){if($item){$saved.Add($item)}}
$errors=[Collections.Generic.List[string]]::new()
$targets=[Collections.Generic.List[string]]::new()
$excludes=@($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$stateDir) + @($payload.exclude_paths)
if($payload.scope -eq 'managed') { $targets.Add([IO.Path]::GetFullPath($payload.managed)) }
else {
    foreach($drive in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
        foreach($item in @(Get-ChildItem -LiteralPath ($drive.DeviceID+'\') -Force -ErrorAction SilentlyContinue)) {
            if($item.Name -in @('$Recycle.Bin','System Volume Information','Boot','EFI','Recovery','pagefile.sys','swapfile.sys','hiberfil.sys','bootmgr','BOOTNXT')){continue}
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
            $skip=$false
            foreach($exclude in $excludes){if($exclude -and $item.FullName.TrimEnd('\') -ieq ([string]$exclude).TrimEnd('\')){$skip=$true}}
            if(-not $skip){$targets.Add($item.FullName)}
        }
    }
}
foreach($path in $targets) {
    try {
        $acl=Get-Acl -LiteralPath $path -Audit
        $existing=@($saved | Where-Object {$_.path -eq $path})
        if($existing.Count) {
            $current=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
            if($current -eq $existing[0].after){continue}
            if($current -ne $existing[0].before){throw 'Audit ACL changed externally; manual review required'}
            $acl.SetSecurityDescriptorSddlForm($existing[0].after,[Security.AccessControl.AccessControlSections]::Audit)
            Set-Acl -LiteralPath $path -AclObject $acl
            $existing[0].after=(Get-Acl -LiteralPath $path -Audit).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
            Save-Json @($saved) $auditFile
            continue
        }
        $before=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
        $inherit=[Security.AccessControl.InheritanceFlags]::None
        if((Get-Item -LiteralPath $path -Force).PSIsContainer){$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}
        $sid=[Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $rights=[Security.AccessControl.FileSystemRights]'ReadData,WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles'
        $rule=[Security.AccessControl.FileSystemAuditRule]::new($sid,$rights,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AuditFlags]::Success)
        $acl.AddAuditRule($rule)
        # Persist intended state before the OS write, enabling recovery after interruption.
        $after=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
        $saved.Add(@{path=$path;before=$before;after=$after})
        Save-Json @($saved) $auditFile
        Set-Acl -LiteralPath $path -AclObject $acl
        $saved[$saved.Count-1].after=(Get-Acl -LiteralPath $path -Audit).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
        Save-Json @($saved) $auditFile
    } catch { $errors.Add($path+': '+$_.Exception.Message) }
}
@{status=$(if($errors.Count){'partial'}else{'configured'});roots=@($targets);errors=@($errors);source='SACL_and_Security_log';requires_inheritance=$true} | ConvertTo-Json -Depth 8 -Compress
