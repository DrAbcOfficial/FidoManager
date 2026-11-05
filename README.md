# FIDO2 Manager

Windows 桌面 FIDO2 安全钥匙管理工具，附带命令行工具 `fido2`。

## 构建与发布

图形界面(NativeAOT 单文件，x64):

```cmd
dotnet publish src\Fido2.Manager\Fido2.Manager.csproj -c Release -p:Platform=x64 -r win-x64
```

命令行工具 `fido2.exe`(同样是 NativeAOT 单文件，发布到同一目录):

```cmd
dotnet publish src\Fido2.Cli\Fido2.Cli.csproj -c Release -r win-x64 -o src\Fido2.Manager\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\publish
```

安装包与便携包会把 `fido2.exe` 放在与 `Fido2.Manager.exe` 相同的目录;需要全局命令时把该目录加入 `PATH` 即可。

调试构建:

```cmd
dotnet build src\Fido2.Manager\Fido2.Manager.csproj -p:Platform=x64
```

测试:

```cmd
dotnet test tests\Fido2.Core.Tests\Fido2.Core.Tests.csproj
```

## CLI

`fido2` 覆盖图形界面的主要能力，便于脚本化操作:

| 命令 | 说明 |
| --- | --- |
| `fido2 devices` | 列出已连接的认证器 |
| `fido2 info` | 查看版本、扩展与能力 |
| `fido2 creds list` | 列出驻留(discoverable)凭据 |
| `fido2 creds export` | 把驻留凭据的公钥导出为 OpenSSH 格式 |
| `fido2 creds delete --id <hex>` | 删除驻留凭据 |
| `fido2 pin state` / `pin set --new` / `pin change --new` | 查看、设置、修改 PIN |
| `fido2 reset` | 恢复出厂设置 |

示例:

```cmd
fido2 devices
fido2 creds list --pin-stdin
fido2 creds export --pin 123456 > keys.pub
fido2 creds export --id a1b2c3 --out id_ed25519_sk.pub
fido2 info --json
```

`creds export`(别名 `ssh`)把每个驻留凭据的 COSE 公钥渲染成 OpenSSH 的
`sk-ssh-ed25519@openssh.com` / `sk-ecdsa-sha2-nistp256@openssh.com` 公钥行，与
`ssh-keygen -t ed25519-sk` 写出的 `.pub` 文件格式完全一致，可直接追加到服务器的
`authorized_keys`。整个过程只读取公钥，不会导出任何私钥材料。

注意事项:

- USB-HID 访问通常需要管理员终端，普通权限下 USB 密钥无法打开。
- `--pin` 会出现在命令历史和进程列表中;脚本里优先使用 `--pin-stdin` 或交互式输入。
- 导出的是凭据公钥本身;只有创建时 RP 为 `ssh:` 的凭据才能直接用于 SSH 登录，
  为其它站点创建的凭据虽能导出正确格式的公钥，但 OpenSSH 不会到对应 RP 下查找凭据。
- `--json` 提供机器可读输出;数据写 stdout，提示与告警写 stderr。

## 界面

- 设备、凭据、指纹、PIN、策略、重置六个页面。
- 凭据页可直接导出选中凭据的 OpenSSH 公钥(`Export SSH key`)，支持复制或保存为 `.pub`。
