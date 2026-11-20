@echo off
setlocal EnableExtensions
cd /d "%~dp0"
echo.
echo  Pruefe alle Dateien gegen PRUEFSUMMEN.txt ...
echo.
powershell -NoProfile -Command "$bad=0; Get-Content 'PRUEFSUMMEN.txt' | ForEach-Object { if ($_ -match '^([0-9a-f]{64})\s+\*?(.+)$') { $h=$matches[1]; $f=$matches[2]; if (Test-Path -LiteralPath $f) { $x=(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower(); if ($x -ne $h) { Write-Host ('ABWEICHUNG: ' + $f) -ForegroundColor Red; $bad++ } } else { Write-Host ('FEHLT: ' + $f) -ForegroundColor Red; $bad++ } } }; if ($bad -eq 0) { Write-Host 'Alle Dateien stimmen mit den Pruefsummen ueberein.' -ForegroundColor Green } else { Write-Host ($bad.ToString() + ' Problem(e) gefunden.') -ForegroundColor Red }"
echo.
pause
endlocal
