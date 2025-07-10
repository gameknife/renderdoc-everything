@echo off
echo Building DLL Wrapper...

REM Create build directory
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
REM Build the project
cmake --build . --config Release

echo Build complete!
pause