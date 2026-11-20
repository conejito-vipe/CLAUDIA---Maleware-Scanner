# CLAUDIA: Python automatisch einrichten (wird von start.bat aufgerufen, nur wenn Python 3.9 oder neuer fehlt).
# Was passiert: Der offizielle Installer wird von python.org geladen, seine digitale Signatur wird geprueft
# (Herausgeber muss "Python Software Foundation" sein), dann wird Python nur fuer das eigene Benutzerkonto
# installiert (keine Administratorrechte). Es wird nichts anderes heruntergeladen oder ausgefuehrt.
param(
    [string]$Arch = "amd64",
    [string]$Log = ""
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Step([string]$Text) {
    Write-Host ("  " + $Text)
    if ($Log) {
        try { Add-Content -Path $Log -Value ("{0} python_setup: {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Text) } catch { }
    }
}

$dst = ""
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ver = "3.12.10"
    switch ($Arch) {
        "arm64" { $name = "python-$ver-arm64.exe" }
        "win32" { $name = "python-$ver.exe" }
        default { $name = "python-$ver-amd64.exe" }
    }
    $url = "https://www.python.org/ftp/python/$ver/$name"
    $dst = Join-Path $env:TEMP ("claudia-" + $name)

    Write-Step ("Lade Python $ver von python.org (" + $name + ") ...")
    Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing

    $sig = Get-AuthenticodeSignature -FilePath $dst
    $subject = ""
    if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
    if ($sig.Status -ne "Valid" -or $subject -notmatch "Python Software Foundation") {
        throw ("Die digitale Signatur des Installers ist nicht in Ordnung (Status: " + $sig.Status + "). Der Installer wird nicht ausgefuehrt.")
    }
    Write-Step "Signatur geprueft: Python Software Foundation, gueltig."

    Write-Step "Installiere Python nur fuer dein Benutzerkonto ..."
    $installArgs = @("/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0", "Include_doc=0", "Shortcuts=0")
    $p = Start-Process -FilePath $dst -ArgumentList $installArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        throw ("Der Installer meldete den Rueckgabewert " + $p.ExitCode + ".")
    }
    Write-Step "Python ist installiert."
    exit 0
}
catch {
    Write-Step ("FEHLER: " + $_.Exception.Message)
    exit 1
}
finally {
    if ($dst -and (Test-Path $dst)) { Remove-Item $dst -Force -ErrorAction SilentlyContinue }
}
