$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json
$name=[string]$payload.name
if($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$'){throw 'Exact package name required'}
$packages=@(Get-AppxPackage -Name $name -ErrorAction Stop | Where-Object {$_.Name -ceq $name})
if($packages.Count -ne 1){throw 'Select one installed package for the current user'}
$p=$packages[0]
@{rule=@{name=$p.Name;collection='Appx';publisher=$p.Publisher;product=$p.Name;binary='*';min_version='0.0.0.0';max_version='*'}}|ConvertTo-Json -Depth 4 -Compress
