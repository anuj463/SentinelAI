$required = @("app.py","requirements.txt","README.md","src\eve_reader.py","src\eve_monitor.py","active-rules\local.rules")
foreach ($item in $required) {
    if (Test-Path $item) { Write-Host "[OK] $item" -ForegroundColor Green }
    else { Write-Host "[MISSING] $item" -ForegroundColor Red }
}
py -3.10 --version
