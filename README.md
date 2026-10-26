# ipcheck

命令行 Claude AI IP 风险检测工具。观测普通检测服务、Cloudflare 与 Claude 官方域名的出口，采集本机代理、DNS、时区与 Claude 端点配置，输出带证据的风险因子和调整建议。

浏览器指纹、WebRTC、DNS 泄露属于浏览器侧检测，本工具不重复实现，请访问 <https://ip.net.coffee/claude/>。

基于 [stormzhang/ipcheck](https://github.com/stormzhang/ipcheck) 与 [yacuo/check-cc](https://github.com/yacuo/check-cc) 的部分实现和思路重新组织。来源、版本、修改及许可证见 [上游记录](docs/upstream-sources.md) 与 [第三方声明](THIRD_PARTY_NOTICES.md)。

## 环境与安装

- Python 3.11+；运行时没有第三方依赖，不需要 Node.js。
- 首版重点验证 macOS；Linux 有部分配置适配，Windows 未覆盖项会单独标注。

直接运行源码，无需 pip 安装或激活虚拟环境：

```bash
cd /Users/helei/Projects/tools/ipcheck
./ipcheck --help
./ipcheck --json
```

以下命令中的 `ipcheck` 在源码运行时均可替换成 `./ipcheck`。

源码开发安装：

```bash
cd /Users/helei/Projects/tools/ipcheck
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e . --no-build-isolation
```

如果环境尚无 setuptools，先执行 `python -m pip install 'setuptools>=77'`。

```bash
pipx install /Users/helei/Projects/tools/ipcheck
```

分发包名为 `ipcheck-local`，命令为 `ipcheck`。它与旧 `ai-ipcheck` 的命令名称相同；开发时优先使用本项目虚拟环境。

## 命令

```bash
ipcheck                       # 终端报告
ipcheck --details             # 展开每项检测的证据与脱敏原始数据
ipcheck --json                # 脱敏 JSON
ipcheck --local               # 仅本地配置摘要，不请求外部检测服务
ipcheck --full                # 网络 + 显式本地检查
ipcheck --reputation          # 查询 Claude 出口类型与信誉（默认开启）
ipcheck --no-reputation       # 关闭第三方类型与信誉查询
ipcheck --timeout 6           # 每次网络请求的超时秒数，范围 1–15
ipcheck --output report.json  # 保存 JSON，仅创建新文件，不覆盖原文件
```

## 终端报告

默认报告分三部分：结论置顶、分区主体、固定页脚。

1. **综合结论**：结论文案与待确认项数量、类别。
2. **Claude 出口**：网页/API 共用出口时合并为一块；分别列出 IP、国家/地区、城市、运营商、ASN、Claude 支持地区、出口时区与响应耗时。
3. **安全检测**：IP 类型（住宅/机房/商业/移动）、信誉评分、代理标记、VPN/Tor/爬虫标记、公开举报记录。
4. **出口对比**：本机直连、代理出口、Cloudflare 出口与一致性说明。
5. **本机配置**：环境变量代理、系统代理、TUN/VPN、本地 DNS、IPv6 配置与出口提示。
6. **时区一致性**：系统、CLI 与 Claude 出口时区，以及一致性判断。
7. **Claude API 配置**：当前进程环境变量与用户 settings 中的端点。
8. **检测建议**：按优先级（高/中/低）排序的结构化建议。

颜色只在交互终端启用：绿色表示已确认正常，黄色表示需核对或建议，红色表示高风险或冲突，灰色表示已跳过或未验证。退出码、`NO_COLOR` 与 `TERM=dumb` 的规则保持不变。窄于 56 列时自动退化为单列。

`--details` 使用同一份报告，追加每项的来源、证据与脱敏 `data`。`--json` 输出完整脱敏报告。

退出码与 `summary.level` 一致：`0` = `clear`，`1` = `attention`，`2` = `incomplete` 或操作失败，`130` = 用户中止。这些不是平台账号安全等级。

## 检测与隐私边界

- 本机直连公网 IP 默认通过 `https://4.ipw.cn/` 与 `https://myip.ipip.net/` 交叉查询，明确禁用系统和环境 HTTP 代理，不修改设置；两项服务会看到该次直连的公网来源 IP。它仍受 TUN/VPN、透明网关和运营商 NAT 影响，不能保证是绕过一切代理的运营商原始 IP。单源成功标记未完成交叉验证，来源不一致保留两者，全部失败不使用代理出口替代。`--local` 不执行此查询。
- 默认网络检查访问 ipify、icanhazip、AWS Check IP、`www.cloudflare.com/cdn-cgi/trace`、ipwho.is，以及 `api.anthropic.com/cdn-cgi/trace` 和 `claude.ai/cdn-cgi/trace`。三个 trace 接口只接收匿名 HTTPS GET，不调用模型，不发送 API Key、Cookie 或登录凭证。各服务会看到对应请求的出口 IP；ipwho.is 会收到指定的观测 IP。
- 默认将 Claude 网页/API 探测到的 IP 发送至 proxycheck.io 与 StopForumSpam 查询类型、信誉和举报记录，相同 IP 复用结果；可用 `--no-reputation` 关闭。关闭后结论标记为不完整，并给出单独建议，不再逐路重复提示。
- Claude 支持地区来自 Anthropic 公布的 [Supported Regions Policy](https://www.anthropic.com/supported-countries)，按出口 IP 的国家代码比对，数据文件记录政策生效日期与核对日期。已列国家的属地与依赖地区按政策视为支持，通过母国代码判定；`XX`、`T1` 等非国家占位码保留为未知。未列出的国家或地区不受支持；这是服务可用范围，不是账号风险评级。
- 响应耗时是 DNS、TLS 与首字节的总耗时，受代理和多条网络路径影响，不代表 Claude 服务可用性或 SLA。
- 出口对比只比较各路径各自观测到的结果。直连与代理路径不同属于预期；只有 Claude 网页与官方 API 互相不一致时才提示核对域名分流，不推断泄露。
- 所有外部查询使用 HTTPS、响应大小限制和超时。出口观测遵循当前进程/系统可识别的代理配置，不保证与其他应用或运行中会话的路径相同。
- IP 归属查询默认遵循代理；失败后仅对 ipwho.is 的指定公网 IP 查询尝试直连，并在报告记录 `lookup_route`。回退查询的仍是原先观测 IP，不替换出口观测、不修改分流规则。
- Claude 探测固定官方 API/网页域名，用以识别当前进程的域名分流。自定义中转、进程/用户代理规则或已登录客户端可能采用其他路径；trace 被阻止或缺字段时保留为未知。Cloudflare `colo` 是服务节点位置，不用来推断用户出口时区。
- IPv6 分开显示“本机 IPv6 配置”“本机 IPv6 地址”“IPv6 出口探测”。macOS 配置通过 IPv4 默认路由定位网络服务，再读取 `networksetup -getinfo`；只对该服务明确返回 Off 时显示“已关闭”。接口检查只保留计数和接口名，不输出原始 IP/MAC。
- IPv6 出口探测并发查询 `api6.ipify.org` 与 `ipv6.icanhazip.com`，任一来源返回有效公网 IPv6 即记录可达及地址。探测遵循当前系统/进程代理；本机即使关闭 IPv6，仍可能经 IPv4 连接代理，由代理访问 IPv6 目标。探测失败不证明本机已关闭，成功也不等于泄露。检测到 IPv6 出口时只提示确认代理是否同时覆盖 IPv4 与 IPv6。
- “Claude API 配置”检查当前进程环境和用户配置；未找到地址时显示“未发现覆盖，默认使用官方 API”，默认行为不代表已确认运行中客户端的实际地址；自定义地址显示域名和“自定义 API，需确认服务商”；不覆盖项目级、受管配置或运行中进程。只输出主机，不输出 URL 凭据、路径或查询参数。
- DNS 只读取系统配置的解析器地址，不是实际递归解析路径；本工具不做主动 DNS 泄露测试。
- 系统代理仅在 macOS 读取启用类型；TUN/VPN 按系统 VPN 连接与常见隧道接口路由识别，已开启不代表覆盖所有流量。
- `--local` 只返回变量名、行号、配置存在性和身份比对数量。不会输出配置原文、邮箱、UUID、API Key 或 Token，不访问钥匙串明文、Cookie 内容和会话文本。
- JSON 包含 IP 等网络环境信息；分享前仍应根据用途检查这些信息。
- 报告不保证账号安全、不预测封号，不自动修改代理、删除配置或重置身份。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

测试只使用人工构造数据及本机临时目录，不调用外部检测服务。

设计见 [架构](docs/architecture.md)、[检测说明](docs/checks.md)；报告格式为 `schemas/report.schema.json`（协议 1.1）。

交互终端显示检测进度、正在执行的项目和累计耗时，完成或中断后清除进度区。`--json`、`--output`、重定向和管道模式不显示动态进度。
