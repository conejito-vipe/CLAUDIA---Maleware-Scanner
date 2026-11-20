# CLAUDIA: Verknuepfung "CLAUDIA.lnk" mit dem Eichhoernchen-Symbol im Programmordner anlegen (wird von start.bat aufgerufen).
# Eine .bat-Datei kann selbst kein Symbol tragen; die Verknuepfung zeigt auf start.bat und bringt das Symbol mit.
# Es wird nur diese eine Datei im Programmordner angelegt, nichts ausserhalb.
param(
    [string]$Folder = "."
)
$ErrorActionPreference = "Stop"
try {
    $root = [System.IO.Path]::GetFullPath($Folder)
    $lnk = Join-Path $root "CLAUDIA.lnk"
    if (Test-Path $lnk) { exit 0 }
    $ico = Join-Path $root "claudia\assets\claudia.ico"
    $shell = New-Object -ComObject WScript.Shell
    $s = $shell.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $root "start.bat"
    $s.WorkingDirectory = $root
    if (Test-Path $ico) { $s.IconLocation = $ico + ",0" }
    $s.WindowStyle = 7
    $s.Description = "CLAUDIA - Website Security and Malware Diagnostics"
    $s.Save()
    exit 0
}
catch {
    exit 1
}
