# T3 卡密接入适配层 · GitHub Actions 一键编译

不用装 Xcode。把仓库推到 GitHub，**Actions 里的 macOS runner 免费帮你编译 dylib、注入主程序、ldid 签名、重打包 IPA**，产物直接下载。

> ✅ 本仓库**已经本地初始化好 git 并提交完毕**，`ci/base.ipa`（基础包，40MB，走 Git LFS）
> 也已经放进去了。你只需要：**在 GitHub 建一个空仓库 → 跑一次 `push.ps1` → 等下产物**。

---

## 最快路径（三步）

### 第 1 步：在 GitHub 建空仓库

打开 https://github.com/new

- Repository name 随便起，比如 `t3-adapter`
- **不要**勾 `Add a README file` / `.gitignore` / `license`（要完全空的）
- Create repository

### 第 2 步：推送

在本目录打开 PowerShell，跑：

```powershell
# 把 YourName / t3-adapter 换成你的
.\push.ps1 -User YourName -Repo t3-adapter
```

脚本会自动：检查 git → 配提交身份（第一次会问你名字邮箱，随便填）→ 启用 LFS → 提交 → 设 remote → 推送。

推送时会弹窗让你登录 GitHub（浏览器授权 或 粘贴 Personal Access Token）。

> 没有 token 就在这里建一个：https://github.com/settings/tokens
> 权限勾 `repo`（私有库）或至少 `public_repo` + `workflow`。

### 第 3 步：拿产物

推送完成后 `ci/base.ipa` 已在仓库里，**CI 会自动跑一次**（不用手动点）。

打开 `https://github.com/<你的用户名>/<仓库名>/actions` → 点最新那次 run → 等 3~6 分钟 → 页面底部 **Artifacts** → 下载 `T3Adapter-产物`：

```
T3Adapter.dylib    ← 编好的适配层
out.ipa            ← 已注入 + 已 ldid 签名 + 已重打包，直接装
```

---

## 仓库结构

```
.
├─ .github/workflows/build.yml     ← CI 主流程（macOS runner）
├─ src/
│   ├─ T3Adapter.m                 ← 适配层源码（卡密门禁）
│   └─ T3Verify.h                  ← 从 T3Gate.dylib 反出的接口
├─ ci/
│   ├─ base.ipa                    ← 基础包（Git LFS，已放好）
│   ├─ inject_dylib.py             ← 往主程序加 LC_LOAD_DYLIB（纯 Python）
│   ├─ extract_ents.py             ← 抽 entitlements 给 ldid
│   └─ selftest.py                 ← 本地自检（不联网）
├─ push.ps1                        ← 一键推送脚本
└─ README.md
```

---

## 想自己手动跑 CI（不用 base.ipa，填直链）

GitHub → Actions → `Build T3Adapter & Repack IPA` → **Run workflow**：

| 输入 | 填什么 |
|---|---|
| `base_ipa` | 基础包的**直链**（留空则用仓库里的 `ci/base.ipa`） |
| `sign_mode` | `adhoc`（越狱机/TrollStore）或 `none`（只出 dylib） |

---

## 三、CI 到底干了什么

```yaml
runs-on: macos-14                     # 免费 macOS runner，自带 Xcode 15 / iPhoneOS17 SDK

- 编 dylib:  xcrun -sdk iphoneos clang -arch arm64 -dynamiclib -fobjc-arc
             -framework UIKit -framework Foundation -framework ObjectiveC
             -install_name @executable_path/T3Adapter.dylib
- 注入:      ci/inject_dylib.py  (往 Diss 头部的空位塞一条 LC_LOAD_DYLIB)
             —— 因为打完 T3Gate 补丁后命令区只用到 0x1AE0，而 __text 从 0x4000 开始，
                有 6.6KB 空位，所以不用搬移段、不用重算 chained fixups
- 抽权限:    ci/extract_ents.py  (保留 platform-application / get-task-allow 等 48 项)
- 签名:      ldid -S  T3Adapter.dylib / T3Gate.dylib / Diss
- 重打包:    zip -r out.ipa Payload
- 上传:      actions/upload-artifact
```

---

## 四、验证清单（拿到包之后）

1. 解包看结构：`unzip -l out.ipa | head` → 顶层必须是 `Payload/`
2. 看注入是否生效：
   ```bash
   otool -L Payload/Diss.app/Diss | grep -E 'T3Gate|T3Adapter'
   # 期望看到：
   #   @executable_path/T3Gate.dylib
   #   @executable_path/T3Adapter.dylib
   ```
3. 看签名：`ldid -e Payload/Diss.app/Diss` 应该有 entitlements 输出

---

## 五、真机日志应该长这样

```
[T3Adapter] === T3Adapter v2 启动 ===
[T3Adapter] 缓存卡密=(无) 到期=(无)
[T3Adapter] 🔒 门禁窗口已建立
[T3Adapter] ✅ 已挂 MainApplicationDelegate didFinishLaunchingWithOptions: (orig=0x...)
[T3Adapter] ✅ RSA 模式初始化成功
[T3Adapter] checkInit = YES
[T3Adapter] === T3Adapter 安装完成 ===
[T3Adapter] didFinishLaunching 归来，重新抬起门禁窗口
[T3Adapter] 校验卡密=XXXXXXXX imei=XXXX
[T3Adapter] 结果 ok=1 msg=验证成功 end=2026-XX-XX XX:XX:XX statecode=XXX
[T3Adapter] ✅ 验证通过，解除门禁
[T3Adapter] 心跳正常，到期 2026-XX-XX XX:XX:XX
```

抓日志：

```bash
idevicesyslog | grep T3Adapter
```

---

## 六、常见问题

**Q: 报 `头部空位不够`**
说明你用的基础包和我打过补丁的不一样（头部没空位）。用 `工作室雷达_T3卡密_v8_适配版.ipa` 当 base。

**Q: 编译报 `'T3Verify.h' file not found`**
确认 `src/T3Verify.h` 已提交，且 `-I "$GITHUB_WORKSPACE/src"` 在编译命令里。

**Q: 运行起来没有卡密窗口**
`T3Verify` 类找不到 = `T3Gate.dylib` 没被加载。看日志里有没有 `❌ T3Verify 类不存在`。
检查 `otool -L` 是否看到 `@executable_path/T3Gate.dylib`。

**Q: 想要正规签名（非越狱机）**
`sign_mode` 用不上，需要你的 p12 + mobileprovision。把证书塞进 GitHub Secrets，
在 workflow 里加 `zsign` 那一步（我可以再给你补）。

**Q: 想改卡密 UI 文案/颜色**
只改 `src/T3Adapter.m` 里的 `T3ALockVC viewDidLoad`，提交后 CI 自动重跑。
