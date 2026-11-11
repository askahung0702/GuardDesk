$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$payload=[Console]::In.ReadToEnd()|ConvertFrom-Json
$path=[IO.Path]::GetFullPath([string]$payload.path)
if($path.IndexOfAny([char[]]'*?[]') -ge 0 -or -not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'Select an existing EXE or MSI file without wildcard characters'}
Import-Module AppLocker -ErrorAction Stop
$before=Get-Item -LiteralPath $path
$info=Get-AppLockerFileInformation -Path $path -ErrorAction Stop
$after=Get-Item -LiteralPath $path
if($before.Length -ne $after.Length -or $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc){throw 'File changed during hashing; retry after update completes'}
$rule=$null
if($info.Publisher){
    $signature=Get-AuthenticodeSignature -LiteralPath $path
    if($signature.Status -ne 'Valid'){throw 'Publisher metadata requires a valid Authenticode signature'}
    $collection='Exe';if($before.Extension -in @('.msi','.msp','.mst')){$collection='Msi'}
    $rule=@{name=$before.Name;collection=$collection;publisher=[string]$info.Publisher.PublisherName;product=[string]$info.Publisher.ProductName;binary=[string]$info.Publisher.BinaryName;min_version='0.0.0.0';max_version='*'}
}
@{path=$path;file_name=$before.Name;sha256=$info.Hash.HashDataString.Substring(2);hash_kind='AppLocker_Authenticode_SHA256';size=$info.Hash.SourceFileLength;rule=$rule}|ConvertTo-Json -Compress -Depth 4
