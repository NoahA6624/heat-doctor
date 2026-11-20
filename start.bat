@echo off
REM Heat Doctor launcher for Windows: installs dependencies on first run, then starts the app.
cd /d "%~dp0"
where python >nul 2>nul || (echo Python 3 is required: https://www.python.org/downloads/ ^(tick "Add python.exe to PATH"^) & pause & exit /b 1)
python -c "import psutil" 2>nul || python -m pip install --user -r requirements.txt
where pythonw >nul 2>nul && (start "" pythonw -m heat_doctor) || (start "Heat Doctor" python -m heat_doctor)
