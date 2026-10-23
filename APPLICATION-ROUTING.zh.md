# Landscape 0.27.1 应用分流扩展

基线为官方 `v0.27.1` / `957afad1dfcb016af9faa35090e57959d7b92aa4`。保留该版本原有功能，新增「应用分流」网页、登录认证后的 `/api/v1/dpi`、完整规则分类器和独立 BPF 应用路由表。

## 网页能做什么

- 从导入的完整应用目录搜索名称、AppID、分类、显式域名和 IP。
- 显示 `category_path`、规则数、域名、域名表达式、IP、CIDR。每类预览最多 16 项，计数保留完整值。这些是规则中的引用，不代表应用全部服务器。
- 按应用选择「电信」或「联通」，保存、应用和停止；显示保存版本与实际运行版本、内核 admission lease、连接数和线路就绪情况。
- `preview` 只做离线模拟，`lab` 只允许固定隔离环境，`live` 使用部署时明确配置的客户端、LAN、BPF 目录和两个 Flow/WAN。网页不能随意提交网口、命令、任意上游地址或扩大客户端范围。

## 实际路由语义

只支持明确配置客户端的新 IPv4 TCP/UDP 连接。完整规则引擎支持原始规则表达式、优先级和跨连接 EXPECT；编译规则不等于已经证明与爱快闭源引擎的全部行为相同。

基于内容的识别通常发生在首个连接建立以后：该连接仍用原出口，端点学习对**同一客户端、目标 IP、端口和协议**的后续新连接生效。TCP 需要新 SYN，UDP 必须额外明确开启。共享 CDN 学习有误判可能；冲突提示会撤回。不能保证选中任何应用就让它第一次连接立刻改走另一个 WAN。

已建立连接固定出口，并与原生 NAT 生命周期、实例 epoch 绑定。策略更新/停止不强行改写旧连接；目标线路不可用、NAT 失效或容量不足时可能丢包，不能静默换线破坏会话。显式原生 Flow 规则优先。IPv6、DNS 到 WAN 亲和、线路故障切换和 SQM 没有因本扩展自动实现。

## 构建与完整库

程序代码随本仓库公开；原始协议数据、完整应用表和家庭配置保留在私有 `ikuai-dpi-bridge` 仓库。此仓库没有固件数据、家庭配置或凭据。

Mac 可构建前端、分类器及运行单元测试。Mac 分类器是 macOS 程序，部署 Linux 时必须使用 Linux 编译产物。主路由程序依赖 Linux/libbpf/Clang 19+；完整编译、内核验证器、真实 NAT 和隔离双出口验收由 `Application routing v0.27.1` 工作流执行。

```sh
cargo test --locked --manifest-path extensions/ikuai-dpi-bridge/Cargo.toml
cargo build --locked --release --manifest-path extensions/ikuai-dpi-bridge/Cargo.toml
python3 -B -m unittest discover -s extensions/ikuai-dpi-bridge/tests -p '*_test.py'
```

Linux 主程序与前端的构建沿用官方 BUILD.zh.md。前端类型由同一源代码生成的 OpenAPI 生成；CI 保存主程序、前端和隔离测试证据。

## 离线准备安装文件

先在 Landscape 原生网页配置好两个单出口 Flow、对应 WAN/PPPoE、NAT 和 LAN。应用选线复用这些原生 Flow，不负责创建拨号或更改接线。

从私有仓库同一版本导出三份文件到一个私有目录：`all-rules.json`、`catalog.json`、`application-map/applications.json`（后者放到目录根）。私有仓库原有定时更新继续生成完整映射，导入前必须核对规则与表格哈希属于同一版本。

```sh
python3 extensions/ikuai-dpi-bridge/deployment/stage_install.py \
  --output /private/tmp/landscape-dpi-install \
  --library /path/to/private-library \
  --binary /path/to/linux/dpi-bridge \
  --client 192.0.2.69 --lan br-lan \
  --pin-root /sys/fs/bpf/landscape/default \
  --telecom-flow 1 --telecom-wan ppp0 \
  --unicom-flow 2 --unicom-wan ppp1
```

参数是示例；网口、Flow 与 BPF 目录必须对应目标测试机。生成目录包含程序、独立随机控制令牌、完整库、配置和 systemd 单元，权限受限。此步骤不安装、不启服务、不更改网络。

由操作者在目标 Linux 上检查后复制该目录内容到 `/`，确认 `python3`、`tcpdump`、`iproute2` 与 `/usr/sbin/bpftool` 可用，再启动 `landscape-dpi.service`。原生网页服务通过默认 `/var/lib/landscape-dpi/control.token` 访问控制器（可用 `LANDSCAPE_DPI_TOKEN_PATH` 调整）。控制器只监听 `127.0.0.1:6310`，浏览器继续使用 Landscape 原有登录。

首次应用必须暂停指定客户端流量并明确确认初始化；控制器会核对实际 LAN TC 程序引用的 map ID、全部 16 个 Flow 出口槽以及原生 NAT hook。无法核对时拒绝应用。保存草稿不等于生效；服务重启后不会凭历史记录宣称规则仍在运行，需重新应用，已有 armed maps 会安全 resume。机器重启后 maps 未初始化时仍需首次确认；本扩展不保证整网无人值守恢复或无缝替代爱快。

更新完整库应先停止应用分流控制服务，整体替换三份同版本文件，再启动并应用保存策略；不要分别热改文件。停止只关闭新连接的应用分流 admission，旧连接跟随原生 NAT 排空。未配置本扩展时，原生 Landscape 转发路径保持原行为。

本次开发和 CI 均不连接家庭 PVE，不启动 VM104，不负责操作者的 PVE/网口或现网切换。
