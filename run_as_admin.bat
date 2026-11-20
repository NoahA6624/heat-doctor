@echo off
REM Starts Heat Doctor with administrator rights so it can read the drive's own temperature sensor.
cd /d "%~dp0"
python -c "import psutil" 2>nul || python -m pip install --user -r requirements.txt
powershell -NoProfile -Command "Start-Process -Verb RunAs -WorkingDirectory '%~dp0' -FilePath pythonw -ArgumentList '-m heat_doctor'"
