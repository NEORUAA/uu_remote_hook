$ErrorActionPreference = 'Stop'
$taskState = Join-Path $PSScriptRoot '.runtime'
$taskPidPath = Join-Path $taskState 'controller.pid'
if (-not (Test-Path -LiteralPath $taskPidPath)) {
    Write-Output 'The controller is not running.'
    exit 0
}
$taskHookPid = [int](Get-Content -LiteralPath $taskPidPath)
if (-not (Get-Process -Id $taskHookPid -ErrorAction SilentlyContinue)) {
    Remove-Item -LiteralPath $taskPidPath
    Write-Output 'Removed a stale controller PID file.'
    exit 0
}
Set-Content -LiteralPath (Join-Path $taskState 'stop') -Value 'stop' -Encoding ascii
for ($taskAttempt = 0; $taskAttempt -lt 50; $taskAttempt++) {
    if (-not (Test-Path -LiteralPath $taskPidPath)) {
        Write-Output 'Quality hook removed.'
        exit 0
    }
    Start-Sleep -Milliseconds 200
}
throw 'The controller did not stop in time. See .runtime\events.jsonl.'
