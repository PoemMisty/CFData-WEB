# iOS (TrollStore) 版

把 CFData-WEB 原样搬到 iOS：**Go 后端一行不改**，编译成 `darwin/arm64` 后把 Mach-O 的平台字段从 macOS 改成 iOS 即可运行；前端仍由后端内置的 `index.html` 提供，用一个 ObjC 壳承载。

```
CFData.app/
├── CFData              ObjC 壳（本目录源码）
├── cfdata-backend      Go 后端（CI 产物，已改成 iOS 平台）
├── Info.plist
└── AppIcon*.png
```

壳启动后端（`posix_spawn`，`-host 127.0.0.1 -port 13335`），再用 `UIWebView` 加载 `http://localhost:13335/`，与 Android 版结构一致。上游后续更新只需替换后端二进制。

## 构建

```sh
# 1. 后端：CI 产出 cfdata-darwin-arm64，本地补平台字段
python3 ios/tools/patch_macho.py cfdata-darwin-arm64 ios/build/cfdata-backend

# 2. 壳（需要 iOS SDK，如 theos/sdks 的 iPhoneOS16.5.sdk）
clang -target arm64-apple-ios14.0 -isysroot "$SDK" -fuse-ld=lld -fobjc-arc -O2 \
  -Iios -framework UIKit -framework Foundation -framework WebKit -framework CoreGraphics \
  -o ios/CFData ios/main.m ios/AppDelegate.m ios/WebViewController.m

# 3. 打包
python3 ios/tools/pack.py
```

签名交给 TrollStore 即可：安装时它会用 CoreTrust 重签整个 bundle。

## 三个必须知道的点

1. **`LC_BUILD_VERSION` 必须改成 iOS**
   `GOOS=ios` 需要 cgo 和 Xcode，CI 上跑不起来；`GOOS=darwin` 的产物结构完全一致，只差平台字段和 framework 路径（iOS 没有 `Versions/A` 目录）。`tools/patch_macho.py` 做这两件事。

2. **`WKWebView` 加载不了 loopback，必须用 `UIWebView`**
   壳申请了 `com.apple.private.security.no-sandbox`（`posix_spawn` 的前提）。在这种进程里，WKWebView 的独立网络子进程访问 `127.0.0.1` / `localhost` 会永久卡在 `didStartProvisional`，JS 探针拿到的是 `about:blank`；Safari 打开同一地址却正常。换成 `UIWebView`（同进程 CFNetwork）后一次就通。

3. **entitlements 要在 IPA 里先签好**
   TrollStore 只保留**已经签进二进制**的 entitlements；未签名的嵌套二进制装完后只有 `TROLLTROLL.*`，`posix_spawn` 直接 `EPERM`。用真机自带的 `ldid -S<entitlements.plist>` 签两个二进制后再打包：

   ```
   platform-application
   com.apple.private.security.no-sandbox
   com.apple.private.security.storage.AppDataContainers
   get-task-allow
   ```

   `no-container` 的组合会让 app 完全不启动，不要用。

## 已验证

iPhone 15,2 / iOS 16.2 / TrollStore：官方扫描 1027 个 IP、AMS 数据中心 130 个、SIN/SG 节点 443 TCPing 正常，WebSocket 已连接，设置与结果表格完整渲染。

## 限制

- 导出走 `localStorage` + `cfdata-export://` 拦截，再由系统文件选择器保存（UIWebView 没有 `WKScriptMessageHandler`）
- 后端启动约 7 秒（启动时会尝试下载 `locations.json`，失败一次），期间显示加载页
- 后台只能通过 `beginBackgroundTask` 续约约 30 秒
