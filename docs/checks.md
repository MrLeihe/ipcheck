# 检测方法与证据

| 检查 | 方法 | 局限 |
| --- | --- | --- |
| 本机直连公网 IP | IPW / IPIP 固定 HTTPS 回显，禁用系统与环境 HTTP 代理 | 不绕过 TUN/VPN 或上游网关；单源不视为交叉验证成功，全部失败不借用代理出口；不代表局域网地址 |
| IPv4 代理出口 | 两个 HTTPS 回显服务并发查询 | 仅表示到这些服务的请求路径；单源失败时结果不完整 |
| Cloudflare 出口 | 匿名 GET `www.cloudflare.com/cdn-cgi/trace` | 代表到 Cloudflare 的路径，Claude 域名可能使用不同分流规则；colo 与服务节点有关 |
| 本机 IPv6 配置 | macOS IPv4 默认接口对应服务的 `networksetup -getinfo` | 只对明确的 Off 显示已关闭；只代表该服务，无法映射 VPN、命令失败保留未知，其他平台暂不支持 |
| 本机 IPv6 地址 | macOS ifconfig 活动接口 | 只保存公网/ULA/链路本地地址计数与公网地址所在接口；不依据地址存在性断言互联网可达 |
| IPv6 出口探测 | 并发查询 api6.ipify.org / ipv6.icanhazip.com，严格验证公网 IPv6 回显 | 任一成功即可确认该次可达及地址，失败来源单独保留；两源 IP 不同提示分流；不等于直连对照或 Claude 路径验证 |
| IP 归属 | ipwho.is 查询指定的已观测 IP；默认代理路径失败时尝试绕过系统/进程代理 | 记录查询路径，回退不替换被查询 IP，且无法绕过 TUN/VPN；数据库可能过期，多出口时只描述被选中的 IP |
| Claude API / 网页出口 | 匿名 GET 官方域名 `/cdn-cgi/trace`，验证 `h` 与公网 `ip`，分别查询 IP 归属并记录响应耗时 | 观测当前进程到该官方域名的路径；不调用模型，不发送密钥或登录凭证；耗时含 DNS/TLS/首字节，不代表服务可用性 |
| Claude 支持地区 | 读取随包数据文件，按出口国家代码比对 Anthropic Supported Regions Policy | 数据需随政策更新；出口国家来自 trace 的 `loc`，可能被代理或中转改变；这是可用范围，不是风险评级 |
| 出口路径对比 | 比较直连、代理、Cloudflare、Claude 网页/API 各自观测到的出口 | 直连与代理不同属预期；仅 Claude 网页与 API 不一致时提示核对分流，不推断泄露 |
| IP 类型与信誉 | 默认查询 Claude 网页/API 实测 IP，proxycheck.io / StopForumSpam，相同 IP 复用；可关闭 | Residential/Hosting 显示疑似住宅/机房；Business 不认定住宅。评分越高风险越高，30 起核对，66 起建议更换；VPN/Tor/爬虫标记只在服务返回时展示。阈值不是 Claude 规则 |
| DNS 配置 | macOS scutil、Linux resolv.conf、Windows PowerShell | 不是实际递归解析器，本工具不做主动泄露测试 |
| 环境代理 | 检查变量是否存在 | 不读出变量值；不能保证连接成功或配置被特定客户端继承 |
| 系统代理 | macOS scutil 解析启用类型 | 其他平台暂不覆盖；配置不代表实际流量路径 |
| TUN / VPN | macOS 系统 VPN 连接 + IPv4/IPv6 路由；Linux 两种地址族的路由表 | 显示已开启/未开启；排除接口限定默认路由、链路本地、多播及拒绝路由。按常见接口名识别；不代表全流量覆盖 |
| 时区 | 系统 IANA、TZ、普通检测出口和两个 Claude 同域名探测出口的归属时区分别展示 | 重点展示本机与 Claude 出口；一致性建议合并到检测建议。Cloudflare colo 不用于推断时区 |
| Claude 端点 | 当前环境及用户 settings 文件 | 逐来源展示，不宣称精确复刻客户端全部设置优先级；不查项目/受管设置 |
| 本地 shell | 可选扫描固定的 shell 配置文件 | 只返回相关变量名与行号，不输出原文；大于 1 MiB 时标记不完整 |
| 账号备份 | 可选在内存比较当前账号与前 100 份备份的 UUID | 只输出数量；缺少比较基准或存在无法读取文件时标记不完整 |
| 遥测文件 | 可选统计 JSON 文件数量 | 不读取事件，不推断上传行为 |

所有网络服务使用固定 HTTPS 目标列表，不使用用户 API Key。Claude 与 Cloudflare 探测只允许固定的公开 trace 路径；归属回退仅允许 ipwho.is 的指定公网 IP 路径。网络超时可通过 CLI 配置为 1–15 秒。任务进度按检查组完成更新。

归属请求回退与出口观测分开：前者只是绕过系统/进程代理查询已经观测到的 IP，无法绕过 TUN/VPN；服务可见实际请求来源；回显与 trace 探测始终沿用原代理路径。返回 IP 与被查询 IP 不一致时拒绝使用数据。Claude API 和网页观测到相同出口时，本组复用一次归属查询。

结果与导出统一脱敏；首次采集即避免记录秘密值，输出正则过滤只是第二层保护。identity UUID 只在 local 检查函数内用于比较，不进入 CheckResult。

## IPv6 解释与边界

本机网络服务配置、活动接口地址、代理程序的运行配置、远端出口能力应分别核对。Ethernet 的 IPv6 Off 不代表 macOS 所有接口都没有 IPv6；utun 和 fe80:: 地址也不能证明代理 TUN 开启或具备公网 IPv6。

展示顺序为本机配置 → 活动地址 → 请求出口，配置关闭与出口未知可以同时存在。外部探测失败仍保留未知与失败原因，不通过关闭配置把失败伪装为成功。

IPv6 外部探测用于观测到指定测试服务的可达性与出口地址，与本机配置读取、活动地址计数的结果独立。至少一个成功时该项 `completed` 只表示观测到有效 IPv6，不表示失败来源已通过验证。检测到 IPv6 出口时，建议核对代理是否同时覆盖 IPv4 与 IPv6。

## 默认报告与结论

默认终端按综合结论、Claude 出口、安全检测、出口对比、本机配置、时区一致性、API 配置、检测建议分区展示。全部检查与原始状态在 `--details` 与 JSON 保留。

`summary.level` 为 `clear` / `attention` / `incomplete`；`clear` 需要网页和官方 API 出口、匹配 IP 的有效评分与类型及举报查询、时区比较与 API 配置完整。第三方中转时，官方探测不能作为其路径证明。高评分、举报命中、网页与 API 分流不一致、出口不在支持地区触发具体建议；时区差异只建议保持环境一致，不推断账号风险。

`summary.advice` 是结构化数组，每项包含 `id`、`priority`（high/medium/low）、`category`、`text`、`check_ids` 与 `action`。CLI 按优先级排序后渲染；JSON 保留完整结构。`summary.focus_ids` 为重点检查 ID。

Claude 归属只复用对应观测 IP 的查询结果，补充 region/city/isp/org/asn 字段；同出口合并，不同出口分别展示。普通检测出口可能经过代理，不标为本机真实 IP。IP 类型、评分、代理标记、VPN/Tor/爬虫标记及 StopForumSpam 收录独立展示；来源未提供的字段不猜测。

公网出口 IP 后显示对应地区；无归属数据时标注“归属未知”。来源数量及查询失败原因保留在 `--details` 与 JSON。一次检测内，相同 IP 的归属请求按访问路径缓存，直连、普通检测及 IPv6 出口的每个地址分别查询，Claude 归属与它们复用数据。
