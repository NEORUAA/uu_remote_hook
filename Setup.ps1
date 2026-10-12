param([string]$PythonPath)
$ErrorActionPreference = 'Stop'
$taskPrefix = @()
if ($PythonPath) {
    $taskPython = $PythonPath
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $taskPython = (Get-Command py).Source
    $taskPrefix = @('-3')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $taskPython = (Get-Command python).Source
} else {
    throw 'Install Python 3.10 or newer, or provide -PythonPath.'
}
& $taskPython @taskPrefix -c 'import sys, struct; assert sys.version_info >= (3, 10), "Python 3.10+ is required"; assert struct.calcsize("P") == 8, "64-bit Python is required"'
if ($LASTEXITCODE -ne 0) { throw 'A usable Python 3.10+ interpreter was not found.' }
$taskEnvironment = Join-Path $PSScriptRoot '.venv'
& $taskPython @taskPrefix -m venv $taskEnvironment
if ($LASTEXITCODE -ne 0) { throw 'Failed to create the virtual environment.' }
$taskVenvPython = Join-Path $taskEnvironment 'Scripts\python.exe'
& $taskVenvPython -m pip install -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Failed to install dependencies.' }
Write-Output 'Setup complete. Run .\Start-QualityHook.ps1.'
