# CFData-Web

CFData-Web 是一个基于 Go 的 Cloudflare IP 测试与筛选工具，提供本地 Web 与 CLI 两种使用方式，支持官方 IP 段扫描、非标目标测试、测速、结果筛选、导出和 GitHub 上传。

[在线演示站](https://cfdata-demo.cce.de5.net/) 仅使用浏览器内虚拟数据，用于预览界面与交互；真实使用请下载正式版本。

![image](img/demo.png)

## 功能

- 官方优选：扫描 Cloudflare IPv4/IPv6，按数据中心继续详细延迟测试。
- 非标优选：上传本地 txt/csv 或填写网络 URL，测试自定义 IP/域名与端口。
- 测速：支持单点测速、批量测速、非标并发测速和测速阈值筛选。
- 导出：支持 CSV/TXT、自定义字段、IP 类型筛选、合格结果筛选。
- 上传：支持将导出结果上传到 GitHub。
- APK：支持 Android WebView 壳运行内置后端。

## 快速开始

从 [Releases](https://github.com/PoemMisty/CFData-WEB/releases/latest) 下载对应平台程序后运行。

默认启动 Web 模式：

```text
服务启动于 http://localhost:13335
当前测速网址: auto
```

浏览器打开终端中的地址即可使用。

CLI 模式：

```bash
./cfdata-linux-amd64 -cli
```

首次使用 CLI 配置文件时会生成模板并退出，编辑配置后重新运行即可。

简单示例：

```bash
# 默认 CLI：按命令行 > 配置文件 > 环境变量 > 默认值自动运行
./cfdata-linux-amd64 -cli

# 官方模式：扫描 IPv4，测试 443 端口，测速地址自动选择
./cfdata-linux-amd64 -cli -mode official -offiptype 4 -offport 443 -offurl auto

# 非标模式：读取本地文件，开启 TLS 和 5 个测速线程
./cfdata-linux-amd64 -cli -mode nsb -nsbfile ip.txt -nsbtls=true -nsbspeedtest 5 -offurl auto
```

## Web 使用

界面顶部「扫描方式」选择器支持 TCPing（默认）和 HTTPing。不同扫描模式的延迟数据不可互相比较，仅同模式内的对比才有意义。

### 扫描方式说明

- **TCPing**：测量 TCP 握手延迟，基准值。
- **HTTPing**：测量 HTTP TTFB（Time To First Byte），延迟比 TCPing 高属正常现象。延迟阈值和渲染颜色已按倍率自动缩放，倍率仅为延迟等级参考值，非精确换算：
  - 无 TLS（HTTP 端口）：×1.3
  - 有 TLS（HTTPS 端口）：×4.0

### 官方优选

1. 选择 IPv4 或 IPv6。
2. 设置测试端口、扫描并发、延迟阈值。
3. 点击“开始扫描与测试”。
4. 扫描完成后选择数据中心继续详细测试。
5. 在详细测试结果中可单点测速或批量测速。

### 非标优选

1. 切换到“非标优选”。
2. 上传 txt/csv，或填写网络 URL（二选一）。
3. 设置备用端口、并发、TLS、结果上限、测速线程、测速阈值等参数。
4. 点击“开始扫描与测试”。
5. 在结果表格查看、筛选、导出或上传。

非标输入推荐格式：

```text
1.2.3.4 443
5.6.7.8 8443
2606:4700::1111 443
1.1.1.1
```

未提供端口时会使用备用端口；备用端口默认随 TLS 模式自动选择，关闭 TLS 为 80，开启 TLS 为 443。

## 测速地址

默认测速地址为 `auto`，表示由后端自动选择内置测速源。

Web 下拉项：

- 自动选择
- Cloudflare
- CM提供
- 移动专属
- 手动输入

CLI 可通过 `-offurl`/`-nsburl` 指定：

```bash
./cfdata-linux-amd64 -cli -offurl auto
./cfdata-linux-amd64 -cli -offurl speed.cloudflare.com/__down?bytes=99999999
./cfdata-linux-amd64 -cli -offurl https://example.com/file.bin
```

说明：测速只读取响应字节流计算速度，不会把测速文件保存到本地。

## 常用参数

```text
-cli              启用 CLI 模式
-mode             official 或 nsb
-scanmode         扫描方式：tcping（默认，TCP 握手延迟）或 httping（HTTP TTFB，延迟比 tcping 高属正常，不同模式数据不可对比）
-offthreads       官方扫描并发数
-nsbthreads       非标扫描并发数
-offport          官方测试/测速端口
-offdelay         官方延迟阈值，单位毫秒
-nsbdelay         非标延迟阈值，单位毫秒
-offurl           官方测速下载地址，默认 auto
-nsburl           非标测速下载地址，默认 auto
-dns              自定义 DNS 服务器
-debug            调试日志等级：false、error、all
-offout           官方输出文件名
-nsbout           非标输出文件名
```

非标常用参数：

```text
-nsbfile          本地输入文件
-nsbsourceurl     网络输入 URL
-nsbfallbackport  非标输入缺省端口；不传时随 TLS 自动使用 443/80
-nsbtls           非标是否启用 TLS
-nsbspeedtest     非标测速线程数，0 表示不测速。多 IP 并发影响实际速度，需要准确应设为 1
-nsbresultlimit   非标延迟测试结果上限
-nsbspeedmin      非标测速合格阈值，单位 MB/s
-nsbspeedlimit    非标测速合格结果上限
```

完整参数可运行：

```bash
./cfdata-linux-amd64 -h
```

## 本地缓存

Web 右上角设置菜单提供“恢复全部默认配置”，会清理本地缓存文件，例如 `ips-v4.txt`、`ips-v6.txt`、`locations.json`、ASN 数据库等。任务运行中不会直接清理，避免影响测试。

## 免责声明

本程序仅限用于学习与研究目的。请在下载后24小时内自行删除。使用本程序时，应自行遵守所在地区的法律法规。作者不对使用本程序所产生的任何后果承担责任。下载或使用本程序即视为已阅读、理解并同意上述声明。

## 致谢

- TG 频道：[CF中转IP](https://t.me/CF_NAT)
- GitHub：[Kwisma/iptest](https://github.com/Kwisma/iptest)

## License

Copyright (C) 2026 PoemMisty

This project is licensed under the GNU General Public License v3.0 or later.
See the LICENSE file for details.
