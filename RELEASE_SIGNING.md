# Android 正式 APK：离线签名方案

## 目标

正式 APK 的长期签名私钥只保存在用户自己的 Android/Termux 私有目录中：

`$HOME/.ppio-private-ai/signing/ppio-private-ai-release.p12`

GitHub Actions **只构建未签名 release APK**。GitHub、PPIO、GHCR 和公开仓库都不应获得 APK release signing private key。

Android 要求 APK 使用签名证书才能安装和更新；同一个应用的后续版本必须保持可接受的签名身份。官方 `apksigner` 可完成签名和签名验证。

## 第一次初始化

在 Termux：

```bash
pkg update
pkg install -y git openjdk-21 apksigner
cd ~
git clone https://github.com/hjf561503-dot/ppio-private-ai.git
cd ppio-private-ai
chmod 700 termux/create-release-key.sh termux/sign-release-apk.sh
./termux/create-release-key.sh
```

脚本会要求设置一个至少 16 字符的 ASCII 强密码，并生成 RSA-4096 / SHA-256 的 PKCS#12 release keystore。

### 必须备份

至少制作两份 `.p12` 加密备份，并分开放置。不要把密码和 `.p12` 放在同一位置。

不要把以下内容上传到 GitHub / PPIO / 聊天：

- `ppio-private-ai-release.p12`
- keystore 密码

公开证书 `release-certificate.pem` 和 SHA-256 指纹不是秘密，可以用于后续校验。

## 每次发布

1. GitHub Actions 运行 `Build unsigned release APK`。
2. 下载 Artifact：`ppio-private-ai-release-unsigned`。
3. 解压得到 `app-release-unsigned.apk`。
4. 将 APK 放到 Termux 可访问的位置。
5. 本地签名：

```bash
cd ~/ppio-private-ai
./termux/sign-release-apk.sh /实际路径/app-release-unsigned.apk
```

脚本会生成：

- `ppio-private-ai-release-signed.apk`
- `ppio-private-ai-release-signed.apk.sha256`

并调用 `apksigner verify --verbose --print-certs` 验证签名。

## 为什么不把 release key 放 GitHub Actions Secret

GitHub Actions Secrets 是合理且常见的 CI/CD 方案，但秘密在获准工作流运行时仍需要注入 Runner。对于本项目的高隐私威胁模型，release signing key 不上传 GitHub，减少一个长期私钥托管方和工作流被篡改后窃取密钥的风险。

代价是：每次正式 APK 更新需要在本机执行一次签名脚本。

## Debug APK

Debug APK 仅用于开发测试。不要把 debug APK 生成的 StrongBox 身份登记为最终服务器设备身份。

正式流程：

1. 验证 debug StrongBox 能力；
2. 卸载 debug APK；
3. 安装使用长期 release key 签名的 APK；
4. 在 release APK 中生成新的永久 StrongBox 设备身份；
5. 只把 release 身份的公钥和 attestation 登记到服务器。
