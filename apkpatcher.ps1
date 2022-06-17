Set-StrictMode -version latest
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptPath = Join-Path -Path $scriptPath -ChildPath apkpatcher
python $scriptPath $args
