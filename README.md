# rkit

自动聚合并转换规则，生成 Loon / Mihomo 等客户端订阅。

## 订阅

| 规则集 | Loon | Mihomo |
|---|---|---|
| Direct | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/manual/direct.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/direct.yaml) |
| Proxy | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/manual/proxy.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/proxy.yaml) |
| Merged | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/merged_rules.list) | [legacy Classical](https://raw.githubusercontent.com/lucere30/rkit/main/cat/merged_rules.yaml), [Domain](https://raw.githubusercontent.com/lucere30/rkit/main/cat/merged_rules_domain.yaml), [IPCIDR](https://raw.githubusercontent.com/lucere30/rkit/main/cat/merged_rules_ip.yaml), [Classical](https://raw.githubusercontent.com/lucere30/rkit/main/cat/merged_rules_classical.yaml) |
| ADLite | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/adlite.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/adlite.yaml) |
| ESPN | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/espn.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/espn.yaml) |
| Bitget | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/bitget.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/bitget.yaml) |
| F1 TV | [list](https://raw.githubusercontent.com/lucere30/rkit/main/lq/generated/f1tv.list) | [yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/f1tv.yaml) |

Mihomo Fake-IP：[fakeip-filter.yaml](https://raw.githubusercontent.com/lucere30/rkit/main/cat/fakeip-filter.yaml)（`behavior: domain`；其余规则集为 `classical`）。


Merged 按客户端独立聚合：Mihomo / sing-box 从 Clash 原生分类和 Loyalsoldier Clash GFW 获取规则；Loon 使用 Loon 原生分类（Proxy、Global、GlobalMedia 同时读取非域名和 *_Domain.list）及 Loyalsoldier Surge GFW。构建器对每个客户端独立去重，保留 Loon 的 User-Agent / URL-REGEX。Mihomo 另输出 domain、ipcidr、classical 原生 behavior 的 YAML；IPCIDR 在引用时应添加 `no-resolve`。旧 `cat/merged_rules.yaml` 继续发布，供旧版 Mihomo 配置暂时使用。

配置与上游：[rkit.yaml](rkit.yaml) · 手动规则：`lq/manual/` · 自定义规则：`custom/` · 自动构建：[Actions](../../actions)

F1 TV：每次构建同时拉取 [MetaCubeX formula1](https://github.com/MetaCubeX/meta-rules-dat/blob/meta/geo/geosite/classical/formula1.yaml) 与 [ACL4SSR F1](https://github.com/ACL4SSR/ACL4SSR/blob/master/Clash/Ruleset/F1.list)，合并去重后生成订阅。MetaCubeX 全量采用；ACL4SSR 通过源级 `include_types: [DOMAIN]` 只采用精确域名项，当前为两个 CDN 主机，后续随该源新增、修改、删除，不引入其赛道、商城或共享服务的整域后缀规则。任一源下载/解析失败或筛选结果为空时保留上次完整结果。`custom/f1tv.list` 仅用于额外手动补充，不再固定上游 CDN。将此规则放在通用 Proxy/Merged 规则之前，并绑定所需策略组。未进行实际账号播放测试。sing-box 随全局目标开关控制，当前关闭。
