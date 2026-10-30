@echo off
setlocal
cd /d "%~dp0"
title Real-Time Network Threat Detection
color 0B

REM Find a Python that has the project packages installed
REM (on this PC plain "python" is 3.11 without them; 3.10 has them).
set "PY="
for %%V in (3.10 3.11 3.12 3.13) do (
    if not defined PY (
        py -%%V -c "import sklearn, streamlit, pandas, kafka" >nul 2>&1 && set "PY=py -%%V"
    )
)
if not defined PY (
    python -c "import sklearn, streamlit, pandas, kafka" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [!] No Python with the required packages was found.
    echo     Install them once with:  py -3.10 -m pip install -r requirements.txt
    pause
    exit /b 1
)

:MENU
cls
echo =================================================================
echo   DATA STREAMING AND ANALYSIS - Real-Time Network Threat Detection
echo =================================================================
echo.
echo   [1] Live demo        (first DDoS attack after ~10 seconds)
echo   [2] Full replay      (whole dataset from the first flow)
echo   [3] Automated test   (checks the pipeline end to end)
echo   [0] Exit
echo.
echo   While streaming:  P = pause / resume     Q = stop
echo   Start Docker Desktop first to stream through Apache Kafka.
echo =================================================================
set "choice="
set /p choice="Choose an option: "

if "%choice%"=="1" ( %PY% run.py demo & pause & goto MENU )
if "%choice%"=="2" ( %PY% run.py full & pause & goto MENU )
if "%choice%"=="3" ( %PY% run.py test & pause & goto MENU )
if "%choice%"=="0" exit /b 0
goto MENU
