# rkit

聚合规则并生成 Loon / Mihomo 订阅，来源与客户端开关见 [rkit.yaml](rkit.yaml)。

- Loon：[手动规则](lq/manual/) · [聚合规则](lq/generated/)
- Mihomo：[规则文件](cat/)
- 修改 `lq/manual/` 或 `custom/`；先排除上游，再追加并去重。不要直接修改生成文件。
- Mihomo 使用 `format: yaml`；`fakeip-filter` 与 `proxy-merged-domain` 用 `behavior: domain`，`proxy-merged-ip` 用 `ipcidr`，其余用 `classical`。IP 引用添加 `no-resolve`。
- Proxy Merged 完整版与拆分版选一种；DNS 策略需同时引用 domain 和 classical。
- sing-box 当前暂停更新，`singbox/` 保留历史输出。

```sh
python -m pip install -e .
python -m unittest discover -s tests
rkit check
rkit build --output .rkit-stage
python tools/validate_clients.py .rkit-stage
```

[Actions](../../actions) 每日自动更新；任一来源失败时保留该规则集的上次完整输出。
