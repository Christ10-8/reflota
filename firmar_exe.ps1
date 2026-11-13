# Firma dist\Reflota.exe con un certificado de firma de codigo (.pfx). SIN PROBAR: requiere un certificado real.
# Uso:  .\firmar_exe.ps1 -Pfx C:\ruta\certificado.pfx      (pide la contrasena del .pfx)
param([Parameter(Mandatory = $true)][string]$Pfx)
$ErrorActionPreference = "Stop"
$signtool = (Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
             Sort-Object FullName -Descending | Select-Object -First 1).FullName
if (-not $signtool) { throw "No encuentro signtool.exe (instala el Windows SDK)." }
$pw = Read-Host "Contrasena del certificado" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
& $signtool sign /f $Pfx /p $plain /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\Reflota.exe
$h = (Get-FileHash dist\Reflota.exe -Algorithm SHA256).Hash
"$h  Reflota.exe" | Out-File dist\Reflota.exe.sha256 -Encoding ascii
Write-Host "Firmado. SHA256 nuevo: $h"
