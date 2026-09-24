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

应用清单声明 `requireAdministrator`(USB FIDO HID 接口需要提权,否则 `CreateFile` 返回 0x5;
实测未提权时连零权限探测都会被拒)。

## 设备兼容性说明

- **Feitian(飞天)096e:0853 等 CTAP 2.1 preview 旧固件**:已在真机验证可被发现与管理。
  该类固件有多处 CBOR 违规——`hmac-secret` 中插入多余 0x00、选项名 `credentialMgmtPreview`
  的 'M' 写成控制字节 0x01、getInfo 尾部截断——`CborDecoder` 的字符串修复与逐条目容错、
  `AuthenticatorOptions` 的子序列匹配已针对性处理;凭据管理走预览命令 0x41 + 旧版
  getPinToken(0x05)配对;getInfo 缺省 pinUvAuthProtocols 时按 CTAP 2.0 规范默认协议 v1。
- **USB-CCID 接口**:仅用于 Token2 厂商串号读取;CTAP2 在 USB-CCID 上不可用(SELECT 回
  6A82/6D00),管理功能走 USB-HID 或 NFC。
- **NFC 读卡器**:仅列出能完成 FIDO applet SELECT + getInfo 探测的设备,USB-CCID 孪生接口自动隐藏。

## 已知限制 / 后续工作

- 凭据 `UpdateUserInformation`(改用户名)的 user.id 需先枚举取回,当前 UI 未暴露;Core API 已备好。
- largeBlobs 未实现(参考实现 PS1 同样未覆盖)。
- Token2 厂商配置位(80 C5)读取未做 UI,串号已显示在设备摘要中。
- 测试:Core 各层均为纯函数式对接,建议按设计文档 §10.4 增补黄金向量单测(CBOR/分帧/pinUvAuth 形状)。