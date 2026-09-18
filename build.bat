@echo off
chcp 65001 >nul

set NAME=Szyfrowanie i deszyfrowanie plików
set FOLDER=dist\%NAME%
set ICON=assets/icon.ico
set MAIN_SCRIPT=main.py
set "PYTHON=.venv\Scripts\python.exe"

if errorlevel 1 (
    echo.
    echo Build failed.
    pause
    exit /b 1
)

xcopy /E /I /Y "lang" "%FOLDER%\lang"
xcopy /E /I /Y "theme" "%FOLDER%\theme"

powershell -Command "Compress-Archive -Path '%FOLDER%\*' -DestinationPath '%NAME%.zip' -Force"

pause