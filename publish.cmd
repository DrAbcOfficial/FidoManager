@echo off
rem NativeAOT single-file publish (x64) for both binaries. Output:
rem   src\Fido2.Manager\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\publish\
rem     Fido2.Manager.exe  (GUI)
rem     fido2.exe          (CLI, sharing the same folder)
setlocal
set GUI=src\Fido2.Manager\Fido2.Manager.csproj
set CLI=src\Fido2.Cli\Fido2.Cli.csproj
set OUT=src\Fido2.Manager\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\publish

dotnet publish %GUI% -c Release -p:Platform=x64 -r win-x64 %* || exit /b 1
dotnet publish %CLI% -c Release -r win-x64 -o "%OUT%" %* || exit /b 1
endlocal
