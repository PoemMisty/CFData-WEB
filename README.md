# CFData-Web

## 项目介绍

CFData-Web 是一个基于 Go 开发的 Cloudflare IP 测试与筛选工具，提供本地 Web/CLI，能够在浏览器/终端中查看扫描进度、测试结果、测速结果和导出数据，适合用于 Cloudflare 相关网络测试、节点筛选和研究验证场景。

<img width="2118" height="1232" alt="image" src="https://github.com/user-attachments/assets/49f03241-9904-47b4-a50a-839062534053" />




## 项目说明（重构前内容）

本程序基于旧版本修改，主要内容如下：

- 🛠 修复测试失败问题
- 🚀 支持多次重复测速
- 📊 全维度 CSV 导出
- 🌐 支持非标反代测试


## 重构优化说明

在旧版本基础上，本版本对架构与实现进行了重构优化：添加CLI模式，后端拆分为多个职责模块，降低耦合并提升可维护性与扩展性；任务模型引入连接级会话状态与统一任务管理，修复并发与状态边界问题；同时完善错误处理机制，在关键流程中增加明确错误边界，并加入运行期资源保护，避免缓存误删与状态异常。

## 使用方法

### 1. 下载启动程序

前往仓库Releases或者点击[Releases](https://github.com/PoemMisty/CFData-WEB/releases/latest)前往下载符合你系统的最新版本，启动运行


#### 例如 Win环境下：

直接打开cfdata-windows-amd64.exe，进入默认Web模式


进入
程序启动后会在终端输出本地监听地址和当前测速网址，例如：

```text
服务启动于 http://localhost:13335
当前测速网址: speed.cloudflare.com/__down?bytes=99999999
```

随后在浏览器中打开对应地址即可进入 Web 界面。

#### 终端运行

`./cfdata-windows-amd64.exe -cli` 进入CLI模式

此模式需要一点点基础，所以不做解释

### 2. 官方优选模式-Web

官方优选模式用于从 Cloudflare IP 段中扫描可用目标并继续做详细测试。大致流程如下：

1. 选择 `IPv4` 或 `IPv6`
2. 选择测试端口
3. 设置扫描并发数
4. 设置延迟阈值
5. 点击“开始扫描与测试”
6. 等待扫描完成后，从数据中心汇总中选择目标数据中心继续详细测试
7. 在详细测试结果中可对单个 IP 进行单点测速，且支持重复测速

### 3. 非标优选模式-Web

非标优选模式适合测试自定义目标，文件内容格式要求为每行一条：

```text
1.2.3.4 443
5.6.7.8 8443
2606:4700::1111 443
```

使用步骤如下：

1. 切换到“非标优选”模式
2. 支持上传 txt/csv 文件或填写网络 URL(二选一);若识别失败，请整理为每行一个目标，格式:IP 空格 端口，例如 1.2.3.4443
3. 设置并发数、延迟阈值、是否开启测速、测速线程、TLS 模式、输出文件名、测速网址等参数
4. 点击“开始扫描与测试”
5. 等待程序完成延迟检测、可选测速以及结果导出
6. 在前端查看结果表格，或直接读取生成的文件

### 5. 精简地址库--Web

按 /24 子网探测 TCP:80 连通性，仅保留活跃子网并覆盖 ips-v4.txt，用于排除不可用网段，缩短后续测试时间，若对结果不满意，可恢复全部默认配置

### 5. 恢复本地缓存--Web

界面右上角设置菜单中提供“恢复全部默认配置”选项。该功能会删除本地缓存的 `ips-v4.txt`、`ips-v6.txt`、`locations.json` 等文件，方便下次重新拉取最新数据。当前版本已增加运行任务保护，在有任务执行时不会直接清理缓存，避免影响正在进行的测试。

## 启动参数

程序支持以下 CLI 参数：

### 首次运行会生成配置文件并自动退出，配置输入优先级：命令行参数 > 配置文件 > 环境变量 > 默认值

### 关于Github TOKEN强烈建议使用限制指定仓库读写权限的TOKEN，并且仓库内无重要数据，防止TOKEN泄露导致不必要的意外

如果出现乱码，请携带`-nocolor`参数启动

### 默认行为: 不带 -cli 时启动 Web 服务；带 -cli 或 -cli=true 时进入 CLI 模式
注意: Go 的布尔参数必须写成 -cli 或 -cli=true，不能写成 -cli true（会导致后续参数被忽略）
CLI 用法: ./combined_refactor_debug -cli -mode=official ...

----------------------------------------
```
通用参数
-h
  说明: 显示帮助信息
  默认: <空>
-port
  说明: Web服务运行端口
  默认: 13335
-user
  说明: Web 认证用户名（不设置则不启用认证）
  默认: <空>
-password
  说明: Web 认证密码（需同时设置 -user，否则不启用）
  默认: <空>
-session
  说明: Web 登录会话有效期（分钟）
  默认: 720
-cli
  说明: 是否启用命令行模式，不带时默认启动 Web（请用 -cli 或 -cli=true，不要写成 -cli true）
  默认: false
-mode
  说明: 运行模式：official 或 nsb
  默认: official
-threads
  说明: 扫描并发数
  默认: 100
-out
  说明: 输出文件名
  默认: ip.csv
-speedtest
  说明: 测速线程数；0 表示不测速
  默认: 5
-progress
  说明: 是否输出进度日志
  默认: true
-nocolor
  说明: 禁用颜色输出（cmd 等不支持 ANSI 的终端可开启避免乱码）
  默认: false
-url
  说明: 测速下载地址
  默认: speed.cloudflare.com/__down?bytes=99999999
-debug
  说明: 是否开启调试输出
  默认: false
-compactipv4
  说明: 精简本地 IPv4 地址库：按 /24 子网测 TCP:80 连通性并覆盖 ips-v4.txt
  默认: false
-config
  说明: CLI 配置文件路径，不存在时在二进制目录自动生成完整模板
  默认: 二进制目录/cfdata-config.json
-format
  说明: CLI 导出格式：csv 或 txt
  默认: csv
-fields
  说明: CLI 导出字段：compact、all、ipport 或逗号分隔自定义字段
  默认: compact
-github
  说明: CLI 导出后上传到 GitHub
  默认: false
-ghrepo
  说明: GitHub 仓库，格式 owner/repo
  默认: <空>
-ghbranch
  说明: GitHub 分支
  默认: main
-ghpath
  说明: GitHub 目标路径；留空时按 -format 自动使用 results/ip.csv 或 results/ip.txt
  默认: <自动>
-ghmessage
  说明: GitHub 提交信息
  默认: update cfdata results
-ghtoken
  说明: GitHub token（不推荐直接写入配置；强烈建议使用仅限制指定仓库读写权限的 token，并确保仓库内无重要数据，避免 token 泄露造成不必要的意外）
  默认: <空>
-ghtokenfile
  说明: GitHub token 文件路径（强烈建议文件内 token 仅限制指定仓库读写权限，并确保仓库内无重要数据）
  默认: <空>
-ghupload
  说明: 快速上传指定文件到 GitHub，不执行测试；需配合 -github
  默认: <空>

CLI 配置优先级：命令行参数 > 配置文件 > 环境变量 > 默认值。默认配置文件 `cfdata-config.json` 会在二进制所在目录首次运行 `-cli` 时自动生成；首次生成后程序会提示退出，建议编辑完整配置后重新开始测试。配置文件会列出全部配置项，并为每项提供中文说明、默认值和可选输入项；同时列出 `format`/`fields` 可输入值与全部可选输出字段。TXT 默认输出为 `ip:port#数据中心-源IP位置`。

Web 上传 GitHub 成功后会在结果操作弹窗显示 Raw 地址，点击 Raw 地址即可复制。
----------------------------------------
官方模式参数
-iptype
  说明: 官方模式 IP 类型：4 或 6
  默认: 4
-testport
  说明: 官方模式详细测试与测速端口
  默认: 443
-delay
  说明: 官方模式延迟阈值（毫秒）
  默认: 500
-dc
  说明: 指定数据中心；不填时自动选择最低延迟数据中心
  默认: <空>
-speedlimit
  说明: 官方模式测速达标结果上限；0 表示关闭官方测速
  默认: 0
-speedmin
  说明: 官方模式测速达标下限，单位 MB/s
  默认: 0.1
----------------------------------------
非标模式参数
-file
  说明: 非标模式输入文件路径
  默认: <空>
-tls
  说明: 非标模式是否启用 TLS
  默认: true
-compact
  说明: 非标模式导出精简表格列
  默认: true
  ```
## 免责声明

本程序仅限用于学习与研究目的。请在下载后24小时内自行删除。使用本程序时，应自行遵守所在地区的法律法规。作者不对使用本程序所产生的任何后果承担责任。下载或使用本程序即视为已阅读、理解并同意上述声明。

## 致谢-代码参考

- TG频道：[CF中转IP](https://t.me/CF_NAT)
- GitHub：[Kwisma/iptest](https://github.com/Kwisma/iptest)

## License

Copyright (C) 2026 PoemMisty

This project is licensed under the GNU General Public License v3.0 or later.
See the LICENSE file for details.
