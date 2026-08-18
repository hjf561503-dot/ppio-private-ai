# Android 客户端说明

当前已构建并正式签名的 APK 是 **StrongBox 设备登记/验证客户端**，不是完整聊天客户端。

实际设备身份实现位于：

`android/app/src/main/java/com/hjf/ppioprivateenroll/StrongBoxManager.java`

当前安全属性：

- P-256 设备私钥由 Android StrongBox 生成且不可导出。
- `setUserAuthenticationParameters(0, ...)`：每次使用设备身份私钥都需要用户认证。
- 使用 Android Key Attestation 生成硬件证明链。
- 登记版本没有 `INTERNET` 权限，不能主动上传注册包。
- 公开注册包只包含 Device ID、公钥和 Attestation 证书链，不包含私钥。

## 尚未完成的生产聊天客户端

真正聊天前还需要在 **同一 applicationId、同一 release 签名** 的后续 APK 更新中加入：

- `INTERNET` 权限和仅连接用户指定端点的网络客户端；
- TLS 证书 SHA-256 pin；
- StrongBox 签名的会话建立；
- 临时 X25519 会话协商；
- HKDF-SHA256 + AES-256-GCM 应用层加密；
- 严格的会话序号/nonce 防重放；
- 本地聊天数据库加密；
- 服务器身份/端点变更确认；
- 设备撤销与恢复流程。

`client-test/private_client.py` 使用普通文件私钥，仅用于协议联调，**不能作为生产安全客户端**。
