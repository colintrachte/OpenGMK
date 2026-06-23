@echo off
setlocal enabledelayedexpansion

:: Loop through all .exe files in the current directory
for %%F in (*.exe) do (
    echo Processing: %%F
    
    :: Call the script. If it fails, the loop will still keep moving.
    call ".\run.bat" "%%F" -o "%%~nF.gmk"
    
    :: Check if the decompiler threw an error code (1 or higher)
    if errorlevel 1 (
        echo [ERROR] Failed to process %%F. Skipping to next file...
        echo.
    )
)

echo Done processing all files.
pause
endlocal