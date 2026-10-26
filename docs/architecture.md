# 架构

Python 标准库实现检测执行、平台适配与终端输出。没有本地服务端，也不包含网页前端；浏览器侧检测（指纹、WebRTC、DNS 泄露）通过固定外链交给外部站点，不在本工具内实现。

## 数据路径

1. CLI 创建 Options。
2. core.runner 以有限并发执行独立检查组，网络组内部同时进行多个出口观测。
   Claude 路由组同时请求两个固定官方域名的公开 trace 接口；Cloudflare 组观测通用出口；时区派生检查在普通网络与 Claude 路由组完成后，按各自 IP 归属生成。
3. 每个检查返回 CheckResult，采集代码不直接打印，也不写入配置。
4. 归属、Claude 信誉、支持地区、出口对比与时区比较在并行任务完成后依次派生。
5. Report.to_dict 统一脱敏；文本、JSON 与文件导出都使用这一边界。

报告协议版本为 1.1。status 描述检查是否完成，severity 描述完成的检查是否需要核对。unknown / unsupported 不进入成功计数；skipped 独立展示。摘要保留完整度，不生成账号安全评分。CLI 退出码直接映射 `summary.level`。

`--local` 不设置 `network_enabled`，报告不会因为缺少 Claude 检查而标记为不完整。

## 扩展

- 检查保持独立函数，外部服务集中在 providers，平台命令集中在 platforms。
- 新增检查时同步协议、文档和测试；若需主动 DNS 验证，应另行定义受控域名/权威解析服务及其隐私边界。
- `checks/claude_route.py` 观测固定官方域名的匿名探测，不读取代理客户端凭证或修改分流配置。`providers/http.py` 只允许固定 HTTPS 主机与路径；直连模式仅允许已知公网 IP 的归属查询和固定的直连回显服务。
- `checks/cloudflare.py` 只请求 `www.cloudflare.com/cdn-cgi/trace`；`checks/region.py` 读取随包的支持地区数据文件。
- `checks/route.py` 只做跨路径对比：直连与代理不同属于预期，只有 Claude 网页与官方 API 不一致才标记为 warning。
- `core/summary.py` 生成综合结论、结构化建议、去重与重点检查 ID。建议项包含优先级、类别与关联检查，CLI 与 JSON 共用同一份结果。

`checks/ipv6.py` 只读采集 macOS 当前网络服务配置及活动接口地址计数，和 network.ipv6 的外部请求观测独立执行；不会因服务配置 Off 而跳过经代理的出口探测。仅存接口名、配置模式和地址类别计数。

`platforms/tunnel.py` 并发读取系统 VPN 和两个地址族的路由，只保存状态与接口名。已连接的系统 VPN 或有效隧道路由可确认开启；仅在所需读取均成功且无匹配时显示未开启。

## 数据与发布

支持地区数据位于 `src/ipcheck/data/claude_regions.json`，随包发布（`pyproject.toml` 的 package-data）。更新政策时同步修改 `verified_at` 与 `effective` 字段。

本工具不含网页资源，发布只打包 Python。
