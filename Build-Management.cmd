@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0."
if errorlevel 1 exit /b 2
python -X utf8 "%~dp0dev\build_management.py" %*
set "GD_BUILD_EXIT=%ERRORLEVEL%"
popd
echo ExitCode=%GD_BUILD_EXIT%
exit /b %GD_BUILD_EXIT%
