# rkit

自动聚合并转换规则，生成 Loon / Mihomo 等客户端订阅。

## 订阅

| 规则集 | Loon | Mihomo |
|---|---|---|
| Direct | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/manual/direct.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/direct.yaml) |
| Proxy | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/manual/proxy.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/proxy.yaml) |
| Proxy Merged | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/proxy-merged.list) | [legacy-compatible Classical](https://raw.githubusercontent.com/lucere30/rkit/main/cat/proxy-merged.yaml), [Domain](https://raw.githubusercontent.com/lucere30/rkit/main/cat/proxy-merged-domain.yaml), [IPCIDR](https://raw.githubusercontent.com/lucere30/rkit/main/cat/proxy-merged-ip.yaml), [Classical](https://raw.githubusercontent.com/lucere30/rkit/main/cat/proxy-merged-classical.yaml) |
| ADLite | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/adlite.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/adlite.yaml) |
| ESPN | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/espn.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/espn.yaml) |
| Bitget | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/bitget.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/bitget.yaml) |
| F1 TV | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/f1tv.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/f1tv.yaml) |

Mihomo Fake-IP：[fakeip-filter.yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/fakeip-filter.yaml)。所有当前 Mihomo 输出使用 `format: yaml`；`behavior` 按下表配置：

| 文件 | behavior | 用途 |
|---|---|---|
| `fakeip-filter.yaml` | `domain` | Fake-IP 过滤 |
| `proxy-merged-domain.yaml` | `domain` | 精确域名和域名后缀 |
| `proxy-merged-ip.yaml` | `ipcidr` | 目标 IP；路由引用添加 `no-resolve` |
| `proxy-merged-classical.yaml` | `classical` | 关键词、进程及其他无法放入原生 domain/IP 集合的规则 |
| `proxy-merged.yaml` 及其余 `cat/*.yaml` | `classical` | 完整集合兼容输出或其他分类 |


Proxy Merged按客户端独立聚合：Mihomo / sing-box 从 Clash 原生分类和 Loyalsoldier Clash GFW 获取规则；Loon 使用 Loon 原生分类（Proxy 和 GlobalMedia 均读取基础文件与对应 *_Domain.list，ProxyLite 单文件）及 Loyalsoldier Surge GFW。两种客户端均已从 Merged 来源移除 blackmatrix7 Global。构建器对每个客户端独立去重，保留 Loon 的 User-Agent / URL-REGEX。Mihomo 另输出 domain、ipcidr、classical 原生 behavior 的 YAML；IPCIDR 在引用时应添加 `no-resolve`。旧 `merged_rules` 兼容订阅已停用；请使用 `proxy-merged`。

配置与上游：[rkit.yaml](rkit.yaml) · 手动规则：`lq/manual/` · 自定义规则：`custom/` · 自动构建：[Actions](../../actions)

## Mihomo 原生拆分配置

见 [proxy-merged 配置片段](examples/mihomo-proxy-merged.yaml)。将三条 `RULE-SET` 放在原来完整集合的位置，并指向同一个策略组；IP 引用保留 `no-resolve`。不要同时加载并引用完整 `proxy-merged.yaml`，否则会重复占用资源。已有服务专用规则、直连规则和最终兜底规则的位置应保持原有意图。

DNS `nameserver-policy` 不能只引用 `proxy-merged-domain`：覆盖去重可能删除已被关键词匹配的显式域名，例如 `google.com` 可由 classical 中的 `DOMAIN-KEYWORD,google` 覆盖。需要保留这些域名的 DNS 策略时，使用配置片段中的 `rule-set:proxy-merged-domain,proxy-merged-classical`，并将示例解析器替换为自己的 DNS。不要把 IP 集合加入域名策略。Mihomo 会提示 classical 在该场景只匹配域名规则；这是预期提示，进程/IP 条件不会参与 DNS 域名判断。此写法以固定验证版本 Mihomo v1.19.33 为准。

## 构建与验证

`rkit check` 检查配置与可编辑输入。`python tools/validate_clients.py .rkit-stage` 先校验配置，再实际启动固定版本 Mihomo，通过仅监听 `127.0.0.1`、带随机口令的临时控制端口等待 provider 初始化，核对 behavior、format 和规则条数，并拒绝解析失败或静默跳过的规则。验证进程在成功、失败或超时后均会清理。`mihomo -t` 单独使用不会完整加载规则文件，不能作为 provider 内容正确的证明。

规则 YAML 使用安全的 `CSafeLoader` 加速，未安装 LibYAML 时回退 `SafeLoader`；序列化往返校验仍保留。`rkit.yaml` 继续使用独立的重复键检查，拒绝重复或非字符串配置键。

`collapse_ip` 只合并同一策略集合内的目标 IPv4/IPv6 网段；`SRC-IP-CIDR` 是源设备地址条件，保持原样，不与目标 IP 混合。保留冗余的源网段不改变匹配结果；当前 Proxy Merged 无源 IP 项，不需要为此增加优化步骤。

F1 TV：每次构建同时拉取 [MetaCubeX formula1](https://github.com/MetaCubeX/meta-rules-dat/blob/meta/geo/geosite/classical/formula1.yaml) 与 [ACL4SSR F1](https://github.com/ACL4SSR/ACL4SSR/blob/master/Clash/Ruleset/F1.list)，合并去重后生成订阅。MetaCubeX 全量采用；ACL4SSR 通过源级 `include_types: [DOMAIN]` 只采用精确域名项，当前为两个 CDN 主机，后续随该源新增、修改、删除，不引入其赛道、商城或共享服务的整域后缀规则。任一源下载/解析失败或筛选结果为空时保留上次完整结果。`custom/f1tv.list` 仅用于额外手动补充，不再固定上游 CDN。将此规则放在通用 Proxy/Merged 规则之前，并绑定所需策略组。未进行实际账号播放测试。sing-box 随全局目标开关控制，当前关闭。
