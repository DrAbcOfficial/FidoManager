@echo off
rem NativeAOT single-file publish (x64). Output:
rem   src\Fido2.Manager\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\publish\
dotnet publish src\Fido2.Manager\Fido2.Manager.csproj -c Release -p:Platform=x64 -r win-x64 %*
