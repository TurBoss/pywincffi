. "C:\code\.ci\vagrant\functions.ps1"

$DIR = Split-Path $MyInvocation.MyCommand.Path

RunScript "$DIR\virtualenv.ps1"
