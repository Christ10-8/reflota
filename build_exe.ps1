# Genera dist\Reflota.exe y dist\Reflota.exe.sha256  (PowerShell, Python 3.8+)
$ErrorActionPreference = "Stop"
python -m pip install --upgrade pyinstaller
pyinstaller --noconfirm --onefile --windowed --name Reflota --icon icon.ico --add-data "icon.ico;." reflota.py
$h = (Get-FileHash dist\Reflota.exe -Algorithm SHA256).Hash
"$h  Reflota.exe" | Out-File dist\Reflota.exe.sha256 -Encoding ascii
Write-Host "Listo: dist\Reflota.exe  (SHA256: $h)"
