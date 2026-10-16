# 离线验证器 / Offline Authenticator

Android 8.0+ 的纯离线 TOTP 验证器，包名 `com.chengjieli.offlineauth`，版本 `1.1.0`（versionCode 2）。

## 功能

- 浅色界面；CameraX 预览与图像分析配合内置 ZXing 扫描 TOTP 二维码，无须下载模型或安装其他扫码 App。
- 扫码预览适配横竖屏及四个旋转方向，相机资源随页面生命周期释放与恢复。
- 本地二维码图片识别、手动输入 setup key；添加前确认服务与账号。
- 多账号（最多 250 个）、搜索、编辑名称、删除确认。
- 6/8 位动态验证码、实时倒计时、点按复制。
- SHA1/SHA256/SHA512、15–120 秒周期；默认 SHA1 / 6 位 / 30 秒。
- 全部或选定账号导出为密码保护的 `.oab` 文件；导入前预览新增和重复数量，确认后合并。
- 单账号显示标准 `otpauth://totp` 二维码，可由另一部设备上的兼容验证器扫描。
- 文件备份和二维码转移都保留原设备账号，不自动删除；导入保留已有账号名称，重复密钥与参数组合会跳过。
- Keystore AES-256-GCM 密钥、随机 IV、版本 AAD、原子文件保存；账号元数据与密钥一并加密。
- 不申请 INTERNET 权限，无服务器、云同步、遥测或广告；只有可选相机权限。
- 关闭系统备份与迁移，密文存于 noBackupFilesDir；正式版阻止截图和录屏。
- 损坏、缺失密钥或认证失败会停止写入，不把无法读取的库当作空库覆盖。

## 使用

1. 在网站安全设置开启身份验证器 / TOTP。
2. 打开应用扫描网站二维码，也可使用手动输入密钥或本地图片识别。
3. 确认账号并保存，把应用显示的验证码填回网站完成绑定。
4. 妥善保存网站提供的恢复码。验证码失败时开启手机“自动设置日期和时间”，等待下一组码后重试。

支持标准 TOTP，不支持微软推送批准、HOTP 或 Steam 自定义验证码。没有云同步，也不自动上传备份。

## 备份与设备转移

### 加密文件

1. 在账号列表点击“账号转移”，选择“导出全部账号”或“选择账号导出”。
2. 设置并确认 8–256 个字符的独立备份密码，再通过系统文件选择器保存 `.oab` 文件。
3. 将文件传到自己的另一部设备，安装本应用，选择“导入加密备份”。
4. 输入备份密码，核对新增和跳过数量，点击“确认导入”。确认前取消不会修改本机账号。
5. 核对两台设备的账号及验证码，并验证新设备可以完成网站登录后，再自行决定是否删除旧设备账号。

导入按 `secret + algorithm + digits + period` 去重，不覆盖已有账号或名称。不同账号发生内部 ID 碰撞时会生成新 ID，保留该账号。每个备份及合并后的本机账号均最多 250 个；文件最多 1 MiB，超过限制会拒绝整次导入。

### 当面扫码

在单个账号的菜单选择“转移此账号”，或在“账号转移”页面选择“显示账号二维码”。用另一部手机扫描后核对验证码。二维码含完整验证密钥，只向自己的设备展示；切到后台后二维码会关闭，转移页面始终禁止截图和录屏。名称含 ASCII 冒号的账号请先修改名称，或使用加密文件转移。

### 本机存储与便携备份的区别

| 项目 | 本机账号库 | `.oab` 便携备份 |
| --- | --- | --- |
| 加密密钥来源 | 本设备 Android Keystore 生成并管理 | 从用户设置的备份密码派生 |
| 加密方式 | AES-256-GCM，随机 IV、版本 AAD、原子保存 | PBKDF2-HMAC-SHA256 600,000 次派生 256 位密钥，AES-256-GCM |
| 跨设备恢复 | 不能通过复制本机密文或系统迁移恢复 | 另一部设备凭备份文件和正确密码导入 |
| 需要保留 | 原应用数据及本设备 Keystore 密钥 | `.oab` 文件及独立备份密码 |

每次便携备份使用随机 16 字节 salt 和 12 字节 IV；文件头的版本、算法、KDF 参数和长度等均纳入认证。导入在派生密钥前校验格式和资源限制，拒绝未知版本、异常参数、错误密码和损坏文件。格式说明见 `TransferCodec.java` 的类注释。

备份密码丢失后无法恢复该文件。卸载应用、清除数据或丢失设备后，本机 Keystore 账号库也无法恢复；此时需要事先保存的便携备份及密码，或网站提供的其他验证方式和恢复码。请在删除原设备数据前验证备份确实可导入。

## 开发与构建

工程采用原生 Java 17 / Android View，使用 Android Gradle Plugin 8.13.2、Gradle Wrapper 8.14.5、compileSdk / targetSdk 36、minSdk 26。

1. 安装 JDK 17、Android SDK platform 36 和 build-tools 35.0.0。
2. 新建 `local.properties`，设置 `sdk.dir=/你的/Android/SDK`。
3. 执行 `./gradlew testDebugUnitTest assembleDebug lintDebug`。调试包额外有 `.debug` 后缀，数据与正式包隔离。
4. 正式构建执行 `./gradlew assembleRelease lintRelease`。若未提供签名配置，产物为未签名 APK。

发布签名需要本地 `signing.properties`（不要提交）：

```properties
storeFile=/你的/发布签名文件.jks
storePassword=你的密码
keyAlias=你的别名
keyPassword=你的密码
```

1.1.0 与 1.0.0 保持相同正式包名，继续使用原发布私钥签名时可直接覆盖安装并保留已有账号，请勿先卸载。私钥不放入源代码压缩包；后续发布必须保留并使用同一签名。自己重新生成签名不能覆盖现有安装，`.debug` 调试包也不能作为正式包的升级。正式版启用 `FLAG_SECURE`；调试版普通账号页面允许截图，包含密码或转移二维码的页面在所有构建中均启用保护。

## 测试

- `./gradlew testDebugUnitTest`：44 项 JVM 单元测试，覆盖 RFC 6238 全部 18 个向量、Base32、时间边界、前导零、URI 解析/导出往返、旋转及反色二维码；便携备份的加密往返、随机 salt/IV、密码错误、篡改、恶意格式、资源上限、去重和 ID 碰撞。
- `VaultStoreTest`：12 项设备测试，覆盖加密往返、多账号、随机 IV、密文篡改、密钥丢失、截断/超长文件、重复记录、严格 JSON schema、原子恢复，以及依据最新账号库合并导入。
- `MainFlowTest`：1 项设备流程测试，覆盖多账号添加、重复拒绝、码值/倒计时、搜索、编辑、删除取消/确认、Activity 重建后持久化。
- `ScanFlowTest`：4 项设备测试，覆盖拒绝相机权限后的替代入口、CameraX 前后台释放及恢复、本地图片识别与非 TOTP 二维码拒绝、四个方向的预览旋转与比例。
- `TransferFlowTest`：6 项设备测试，覆盖加密文件导出与预览后导入、错误密码和取消确认、系统文件选择器取消、加密期间切后台、标准账号二维码及后台关闭、旋转取消待处理导入。

设备测试集共 23 项；以上是测试覆盖清单，不表示设备测试已经通过，实际结果以本次运行报告为准。

设备测试只针对 `.debug` 测试包，主流程和转移用例会清空该测试包的账号。请勿在测试包保存真实账号。相机权限测试需要允许用例撤销/授予调试包权限；手动运行前可先撤销：

```sh
adb shell pm revoke com.chengjieli.offlineauth.debug android.permission.CAMERA
./gradlew connectedDebugAndroidTest
```

## 开源与协议

- AndroidX CameraX 1.5.3：`camera-core`、`camera-camera2`、`camera-lifecycle`、`camera-view`，Apache License 2.0。
- AndroidX Activity 1.10.1，Apache License 2.0。
- ZXing core 3.5.4，Apache License 2.0。
- 第三方许可证、版权和 NOTICE 资产统一放在 `app/src/main/assets`，随 APK 打包；重新分发时须保留，包括 `ZXing-LICENSE.txt` 和 `ZXing-NOTICE.txt` 以及 AndroidX 的相关许可声明。
- CameraX 官方文档：[概览](https://developer.android.com/media/camera/camerax)、[实现预览](https://developer.android.com/media/camera/camerax/preview)。
- TOTP：[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)。
- URI：[Google Authenticator Key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)。

本项目的验证只使用合成测试账号和公开测试密钥，未导入用户截图中的二维码。

## 本地项目目录

Android 工程位于本目录根部，可直接运行 `./gradlew`。已交付的 APK、源码快照、说明和校验记录位于 `outputs/`；测试资料、日志、模拟器与本地签名位于 `work/`。发布签名配置使用 `work/signing/`，这些本地文件不纳入 Git。
