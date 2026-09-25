@echo off
REM Common Python Payload Shield - PyPI Publishing Script
REM This script builds and publishes the package to PyPI
REM GitHub: https://github.com/PayloadShield/ComPyPS
REM
REM Authentication (in priority order):
REM   1. PYPI_TOKEN environment variable  (set PYPI_TOKEN=pypi-xxxx)
REM   2. %USERPROFILE%\.pypirc file
REM   3. Interactive prompt (asks for token at runtime)

setlocal enabledelayedexpansion

echo.
echo ========================================
echo Common Python Payload Shield - PyPI Publisher
echo ========================================
echo.

REM Check if running from the correct directory
if not exist "pyproject.toml" (
    echo Error: pyproject.toml not found. Please run this script from the project root directory.
    exit /b 1
)

REM Check Python installation
python --version > nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    exit /b 1
)

REM -------------------------------------------------------
REM [1/6] Install / upgrade build tools
REM -------------------------------------------------------
echo [1/6] Ensuring build tools are installed...
python -m pip install --upgrade pip build twine >nul 2>&1
if errorlevel 1 (
    echo Error: Failed to install build tools. Run manually:
    echo   python -m pip install --upgrade pip build twine
    exit /b 1
)
echo      Done.

REM -------------------------------------------------------
REM [2/6] Resolve PyPI credentials
REM -------------------------------------------------------
echo [2/6] Resolving PyPI credentials...

set "CRED_SOURCE="
set "TWINE_UPLOAD_ARGS="

REM Priority 1: PYPI_TOKEN environment variable
if defined PYPI_TOKEN (
    echo      Using PYPI_TOKEN environment variable.
    set "TWINE_USERNAME=__token__"
    set "TWINE_PASSWORD=!PYPI_TOKEN!"
    set "CRED_SOURCE=env"
    goto :cred_resolved
)

REM Priority 2: Existing .pypirc
if exist "%USERPROFILE%\.pypirc" (
    echo      Using existing %USERPROFILE%\.pypirc
    set "CRED_SOURCE=pypirc"
    goto :cred_resolved
)

REM Priority 3: Ask the user for a token interactively
echo.
echo      No credentials found. You need a PyPI API token to publish.
echo      Get one at: https://pypi.org/manage/account/token/
echo.
set /p "USER_TOKEN=      Paste your PyPI API token (pypi-...): "

if not defined USER_TOKEN (
    echo Error: No token provided. Cannot publish without credentials.
    echo.
    echo To avoid this prompt, do ONE of the following:
    echo   a) Set environment variable:  set PYPI_TOKEN=pypi-xxxx
    echo   b) Create %USERPROFILE%\.pypirc  (see instructions below)
    echo.
    goto :show_pypirc_help
)

REM Validate token prefix (use substring to avoid piping the raw token)
if not "!USER_TOKEN:~0,5!"=="pypi-" (
    echo.
    echo Warning: Token does not start with "pypi-". PyPI API tokens should start with "pypi-".
    echo          Proceeding anyway, but upload may fail.
    echo.
)

set "TWINE_USERNAME=__token__"
set "TWINE_PASSWORD=!USER_TOKEN!"
set "CRED_SOURCE=prompt"

REM Offer to save token to .pypirc for next time
echo.
set /p "SAVE_TOKEN=      Save token to %USERPROFILE%\.pypirc for future use? (y/N): "
if /i "!SAVE_TOKEN!"=="y" (
    REM Use Python to write .pypirc safely (avoids batch special-char issues)
    python -c "import os, sys; f=open(os.path.join(os.path.expanduser('~'), '.pypirc'), 'w'); f.write('[distutils]\nindex-servers = pypi\n\n[pypi]\nusername = __token__\npassword = ' + os.environ['TWINE_PASSWORD'] + '\n'); f.close()"
    echo      Saved! Future publishes will use .pypirc automatically.
)

:cred_resolved
echo      Credentials ready [source: !CRED_SOURCE!]

REM -------------------------------------------------------
REM [3/6] Clean previous builds
REM -------------------------------------------------------
echo [3/6] Cleaning previous builds...
if exist "build\" (
    rmdir /s /q build 2>nul
)
if exist "dist\" (
    rmdir /s /q dist 2>nul
)
for /d %%X in (*.egg-info) do (
    rmdir /s /q "%%X" 2>nul
)
echo      Done.

REM -------------------------------------------------------
REM [4/6] Build distribution packages
REM -------------------------------------------------------
echo [4/6] Building distribution packages...
python -m build
if errorlevel 1 (
    echo.
    echo Error: Build failed. Check the output above for details.
    exit /b 1
)
echo      Build successful.

REM -------------------------------------------------------
REM [5/6] Verify package
REM -------------------------------------------------------
echo [5/6] Verifying package with twine check...
python -m twine check dist/*
if errorlevel 1 (
    echo.
    echo Error: Package verification failed. Fix the issues above before publishing.
    exit /b 1
)
echo      Package OK.

REM -------------------------------------------------------
REM [6/6] Upload to PyPI
REM -------------------------------------------------------
echo.
echo [6/6] Publishing to PyPI...
echo.
echo ========================================
echo Package Information:
echo ========================================
python -c "import re; content = open('pyproject.toml').read(); name = re.search(r'name = \"([^\"]+)\"', content); version = re.search(r'version = \"([^\"]+)\"', content); print(f'  Name:    {name.group(1)}') if name else None; print(f'  Version: {version.group(1)}') if version else None; print(f'  Repo:    https://github.com/PayloadShield/ComPyPS')"
echo ========================================
echo.

REM Upload with --non-interactive to prevent hanging on missing creds
python -m twine upload dist/* --non-interactive --skip-existing --verbose
if errorlevel 1 (
    echo.
    echo ========================================
    echo   Upload FAILED
    echo ========================================
    echo.
    echo Troubleshooting:
    echo   1. Make sure your PyPI API token is valid
    echo      Get a new one: https://pypi.org/manage/account/token/
    echo   2. If this version already exists on PyPI, bump the version
    echo      in pyproject.toml and re-run this script
    echo   3. Check your internet connection
    echo.
    exit /b 1
)

echo.
echo ========================================
echo   SUCCESS - Package published to PyPI!
echo ========================================
echo.
echo   View:    https://pypi.org/project/ComPyPS/
echo   Install: pip install ComPyPS
echo   GitHub:  https://github.com/PayloadShield/ComPyPS
echo.

endlocal
exit /b 0

:show_pypirc_help
echo.
echo ========================================
echo How to create a .pypirc file:
echo ========================================
echo.
echo Create %USERPROFILE%\.pypirc with this content:
echo.
echo   [distutils]
echo   index-servers = pypi
echo.
echo   [pypi]
echo   username = __token__
echo   password = pypi-YOUR-TOKEN-HERE
echo.
echo Or simply set an environment variable:
echo   set PYPI_TOKEN=pypi-YOUR-TOKEN-HERE
echo.
echo To make it permanent (survives reboots):
echo   setx PYPI_TOKEN pypi-YOUR-TOKEN-HERE
echo.
endlocal
exit /b 1
