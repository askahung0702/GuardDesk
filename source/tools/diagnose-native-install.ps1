# Administrator-only troubleshooting for this project's reviewed installer.
# No credentials or endpoint config contents are written to the event log.
$ErrorActionPreference='Stop'
$sourceName='GuardDeskPilot Installer'
$root=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$identity=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator approval is required.'}
if(-not [Diagnostics.EventLog]::SourceExists($sourceName)){[Diagnostics.EventLog]::CreateEventSource($sourceName,'Application')}
try {
    $package=Join-Path $root 'dist\GuardDesk'
    $auditStatus=& (Join-Path $package 'GuardDesk.exe') process-audit-status
    if($LASTEXITCODE -ne 0){throw 'Windows native audit query preflight failed; existing worker has not been stopped.'}
    [Diagnostics.EventLog]::WriteEntry($sourceName,('GuardDesk audit query preflight: '+[string]$auditStatus),[Diagnostics.EventLogEntryType]::Information,1002)
    $installer=Join-Path $package '_internal\guarddesk\windows\install-usb.ps1'
    & $installer -Action Install -SourceDirectory $package -SourceConfig (Join-Path $root 'runtime\agent\config.json')
    if($LASTEXITCODE -ne 0){throw ('Installer exit code: '+$LASTEXITCODE)}
    [Diagnostics.EventLog]::WriteEntry($sourceName,'GuardDesk native installer completed.',[Diagnostics.EventLogEntryType]::Information,1000)
} catch {
    $message='GuardDesk native installer failed. '+$_.Exception.Message+' | '+$_.FullyQualifiedErrorId+' | line '+$_.InvocationInfo.ScriptLineNumber
    if($message.Length -gt 3000){$message=$message.Substring(0,3000)}
    [Diagnostics.EventLog]::WriteEntry($sourceName,$message,[Diagnostics.EventLogEntryType]::Error,1001)
    exit 1
}
