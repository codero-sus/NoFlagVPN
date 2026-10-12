@echo off
rem Update this NoFlagVPN checkout.  The work is done by updater.py so that the
rem batch, shell and direct invocations all behave the same; this file only
rem finds an interpreter and hands over.
rem
rem   updater.bat              update to the tip of this branch
rem   updater.bat --check      report whether an update exists (exit 10 if yes)
rem   updater.bat --force      update even with local changes (they are stashed)
rem
rem NoFlagVPN needs Python 3.10+ to run, so a Python interpreter is guaranteed to
rem exist wherever this is useful.

setlocal enableextensions

set "HERE=%~dp0"

rem A virtualenv inside the checkout is where nfvpn was installed, so the pip
rem step should land there rather than in a system interpreter.
if exist "%HERE%.venv\Scripts\python.exe" (
    "%HERE%.venv\Scripts\python.exe" "%HERE%updater.py" %*
    exit /b
)

if defined NFVPN_PYTHON (
    "%NFVPN_PYTHON%" "%HERE%updater.py" %*
    exit /b
)

rem "py -3" is the launcher shipped with python.org installers and picks the
rem newest Python 3; plain "python" covers Microsoft Store and conda installs.
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%HERE%updater.py" %*
    exit /b
)

where python >nul 2>nul
if not errorlevel 1 (
    python "%HERE%updater.py" %*
    exit /b
)

echo updater: no Python found on PATH.
echo   Install Python 3.10 or newer from https://www.python.org/downloads/
echo   Retry with the full path in NFVPN_PYTHON, or update with: git pull
exit /b 1
