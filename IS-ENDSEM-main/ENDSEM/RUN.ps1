param([string]$Program = 'find_answer.py', [Parameter(ValueFromRemainingArguments=$true)][string[]]$ProgramArgs)
$ErrorActionPreference = 'Stop'
$bundledPython = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
if (Test-Path -LiteralPath $bundledPython) { $examPython = $bundledPython }
else { $examPython = (Get-Command python).Source }
Push-Location $PSScriptRoot
try { & $examPython $Program @ProgramArgs; exit $LASTEXITCODE }
finally { Pop-Location }
