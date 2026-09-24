# FIDO2 Manager

Windows 桌面 FIDO2 安全钥匙管理工具

## 构建与发布

```cmd
dotnet publish src\Fido2.Manager\Fido2.Manager.csproj -c Release -p:Platform=x64 -r win-x64
```

调试构建:

```cmd
dotnet build src\Fido2.Manager\Fido2.Manager.csproj -p:Platform=x64
```