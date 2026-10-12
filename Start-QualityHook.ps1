param([string]$PythonPath)
$ErrorActionPreference = 'Stop'
$taskPython = if ($PythonPath) { $PythonPath } else { Join-Path $PSScriptRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $taskPython -PathType Leaf)) {
    throw 'Run .\Setup.ps1 first, or provide -PythonPath.'
}
$taskState = Join-Path $PSScriptRoot '.runtime'
$taskPidPath = Join-Path $taskState 'controller.pid'
$taskStatusPath = Join-Path $taskState 'status.json'
if (Test-Path -LiteralPath $taskPidPath) {
    $taskHookPid = [int](Get-Content -LiteralPath $taskPidPath)
    $taskExisting = Get-CimInstance Win32_Process -Filter "ProcessId=$taskHookPid"
    $taskScriptPath = Join-Path $PSScriptRoot 'quality_hook.py'
    if ($taskExisting -and $taskExisting.CommandLine -like "*$taskScriptPath*") {
        if (Test-Path -LiteralPath $taskStatusPath) { Get-Content -LiteralPath $taskStatusPath }
        Write-Output 'The controller is already running.'
        exit 0
    }
}
New-Item -ItemType Directory -Path $taskState -Force | Out-Null
$taskScript = Join-Path $PSScriptRoot 'quality_hook.py'
$taskToken = [guid]::NewGuid().ToString('N')
$taskProcess = Start-Process -FilePath $taskPython -ArgumentList @('-u', "`"$taskScript`"", '--startup-token', $taskToken) -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $taskState 'stdout.log') -RedirectStandardError (Join-Path $taskState 'stderr.log')
for ($taskAttempt = 0; $taskAttempt -lt 50; $taskAttempt++) {
    $taskProcess.Refresh()
    if ($taskProcess.HasExited) {
        Get-Content -LiteralPath (Join-Path $taskState 'stderr.log') -ErrorAction SilentlyContinue
        throw 'The controller exited before becoming ready.'
    }
    if (Test-Path -LiteralPath $taskStatusPath) {
        $taskStatus = Get-Content -LiteralPath $taskStatusPath -Raw | ConvertFrom-Json
        if ($taskStatus.startup_token -eq $taskToken -and $taskStatus.phase -ne 'starting') {
            if ($taskStatus.phase -eq 'ready') {
                Write-Output 'The quality hook is ready.'
            } elseif ($taskStatus.phase -eq 'waiting') {
                Write-Output 'The controller is running and waiting for UU Remote.'
            } else {
                throw "The controller reports '$($taskStatus.phase)'. See .runtime\events.jsonl."
            }
            exit 0
        }
    }
    Start-Sleep -Milliseconds 200
}
throw 'Readiness timed out. See .runtime\stderr.log and .runtime\events.jsonl.'
