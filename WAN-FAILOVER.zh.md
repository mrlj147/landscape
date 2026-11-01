# 多 WAN 主备切换

开发版本：`0.28.0-wan-failover.1`，基于 `main` 的 `0.28.0`。

在“分流规则 → 编辑”中打开“启用 WAN 主备切换”，添加至少两条不同的 WAN。
列表第一项是主 WAN，其余按顺序备用；“提高优先级 / 降低优先级”可调整主次。
主备模式每次只使用一个出口，忽略权重。关闭自动切换后，始终固定使用列表第一项的主 WAN；
即使主 WAN 无法访问外网，也不切到备用。需要重新使用权重分流时，单独点击“恢复权重分流模式”。
默认关闭主备功能，旧配置和数据库升级不会自动改变流量出口。

使用前先在每条 WAN 的“健康检测”中启用探测：

- **Ping**：保持现有多目标 ICMP 检测。
- **HTTP / HTTPS**：例如 `https://www.baidu.com`，并指定上游 DNS 的 IPv4 地址。
  DNS 解析和 HTTP 连接都固定走当前 WAN，不使用系统 DNS、代理或另一条 WAN。
  2xx / 3xx 响应算成功，4xx / 5xx、连接失败、TLS 错误和超时算失败。不跟随跳转。
- **DNS**：指定上游 DNS IPv4 地址和查询域名，例如 `223.5.5.5`、`www.baidu.com`。
  发送真实 UDP DNS A 查询，校验应答来源、事务 ID 和问题；需要成功返回 A 记录。
  SERVFAIL、NXDOMAIN、无 A 记录、截断响应和超时算失败。

探测间隔、超时、失败次数和恢复次数可配置。默认每 10 秒一轮、单轮超时 1 秒，
连续失败 3 轮判故障，已判故障的线路连续成功 3 轮恢复。网页探测可按实际延迟增大超时。
断线导致 WAN 路由消失时直接触发出口重选，不必等探测超时。
仅有路由存在且健康状态为正常的 WAN 可被选中；启动、探测停止或尚无结论时不会作为备用接管。

“主 WAN 恢复后自动切回”默认打开。关闭时保留仍健康的当前备用出口；修改出口顺序或
重新打开自动回切可重新按主次选择。备用也故障时继续向后寻找可用出口。
全部不可用时移除该分流的出口，等待恢复，不擅自使用未配置的 WAN。

IPv4 / IPv6 分别检查各自的 WAN 路由是否存在，目前健康依据来自 IPv4 探测。
这不是独立的 IPv6 连通性检测，也不保证已有 TCP、游戏或 NAT 会话无感迁移；应用可能需要重连。
本功能作用于启用主备的分流规则，不修改默认分流、路由器系统默认路由，或显式绑定某条 WAN 的 DNS 上游配置。
DNS 模式是线路健康探测，不是更换 DNS 服务器。

## 验证

```sh
cargo test --locked -p landscape-common -p landscape-core -p landscape-database -p migration --lib
cargo test --locked -p landscape --lib wan_link_service::
./gen_ts_bindings.sh
pnpm --filter landscape-webui test
pnpm --filter landscape-webui build
```

Linux 实机验收：设置 WAN1 主、WAN2 备，观察路由和新连接出口；依次断开 WAN1、
仅阻断 WAN1 探测目标、恢复 WAN1、交换主次、关闭主备、同时中断两线，检查行为与设置一致。
验证备用接管后 WAN1 的探测仍固定走 WAN1，避免通过备用线路探测造成误回切。
