# Android 生产客户端说明

`StrongBoxIdentity.kt` 只实现生产设备身份的核心：P-256 私钥必须由 Android StrongBox 生成且不可导出，并要求生物识别/设备凭据后才能签名。

最终 App 还需要：

- 将 `publicKeyPem()` 注册到服务器 `TRUSTED_DEVICES_JSON_B64`
- 对每个请求构造与服务器完全一致的 canonical string
- TLS 证书 SHA-256 pin
- 临时 X25519 会话协商
- AES-256-GCM 加密/解密
- 本地聊天数据库加密
- Key Attestation 验证 StrongBox 安全级别和证书链
- 设备撤销和恢复流程

当前 `client-test/private_client.py` 用普通文件私钥，只用于把服务器跑通，**不是最终安全客户端**。
