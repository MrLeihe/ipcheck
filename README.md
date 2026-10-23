# ipcheck

命令行 + 本地网页的环境诊断工具。分别观测普通检测服务与 Claude 官方域名的出口，采集本机代理/DNS/时区、Claude 端点配置和浏览器特征，以证据和检测完整度解释结果。

基于 [stormzhang/ipcheck](https://github.com/stormzhang/ipcheck) 与 [yacuo/check-cc](https://github.com/yacuo/check-cc) 的部分实现和思路重新组织。来源、版本、修改及许可证见 [上游记录](docs/upstream-sources.md) 与 [第三方声明](THIRD_PARTY_NOTICES.md)。

## 环境与安装

- Python 3.11+；Python 运行时没有第三方依赖。
- 网页源码检查和资源生成需要 Node.js 22.12+ 与 npm；发布包包含网页资源时，使用者不需要 Node。
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

如果环境尚无 setuptools，先执行 `python -m pip install 'setuptools>=77'`。这是安装包入口所需的元数据工具，不是诊断工具的运行时依赖。也可以跳过安装，直接用 `PYTHONPATH=src python3 -m ipcheck`。

安装已经准备好网页资源的项目到 pipx：

```bash
pipx install /Users/helei/Projects/tools/ipcheck
```

分发包名为 `ipcheck-local`，命令为 `ipcheck`。它与旧 `ai-ipcheck` 的命令名称相同；开发时优先使用本项目虚拟环境。

## 命令

```bash
ipcheck                       # 双列表格展示检测结果
ipcheck --details             # 展开检测证据与脱敏原始数据
ipcheck --json                # 脱敏 JSON
ipcheck --local               # 仅本地配置摘要，不请求外部检测服务
ipcheck --full                # 网络 + 显式本地检查
ipcheck --reputation          # 额外的第三方信誉查询
ipcheck --timeout 6           # 每次网络请求的超时秒数，范围 1–15
ipcheck --output report.json  # 保存 JSON，仅创建新文件，不覆盖原文件
ipcheck web                   # 启动本地网页并打开浏览器
ipcheck web --no-browser      # 只打印本机会话地址
ipcheck web --allow-local     # 允许网页选择本地摘要检查
```

网页默认监听 `127.0.0.1:8765`；使用 `--port 0` 选择空闲端口。`ipcheck web` 本身不发起检测，点击页面按钮后才运行。浏览器数据只发送到本机服务。退出服务会丢弃内存中的报告和会话凭证，显式导出的文件除外。

终端采用双列表格：左列为项目名，右列直接展示 IP、DNS、代理状态和时区等结果；归属数据按国家/地区、城市、运营商和 ASN 分行展示。边框按网络、归属、代理/信誉、时区、Claude、本地摘要等板块分区，颜色突出关键结果和需核对项；未验证、不支持及跳过项明确标注。证据和原始数据默认折叠，使用 `--details` 展开。表格按终端宽度换行，窄于 56 列时改为单列框；仅在交互终端启用颜色，重定向、`TERM=dumb` 或设置 `NO_COLOR` 时输出纯文本。`--json` 和导出的报告协议保持一致。

时区区块分别展示系统、CLI、检测出口、Claude API 出口和 Claude 网页出口的时区。后三者来自各自观测 IP 的地理数据库归属；例如普通检测请求走马来西亚、AI 域名走台湾时，可分别显示 `Asia/Kuala_Lumpur` 与 `Asia/Taipei`。这些值是各次请求出口的归属时区，不是 Claude 服务端或登录会话的本地时区。时区区块末尾始终显示一个“时区建议”：以 Claude 网页出口为参照，IANA 名称和当前偏移都一致时显示绿色“一致”，存在差异时黄色提示可考虑采用的时区，缺数据时黄色提示补全；不再分别列出普通出口/API 的无需调整说明。CLI 模式参考系统时区，不把 CLI 的 `TZ` 当成浏览器时区；本地网页采样后改用实际浏览器时区。普通/API 出口比较保留在汇总数据中。当前偏移相同不代表 IANA 名称相同，也不能据此判断账号风险。浏览器通常跟随系统设置，也可能被覆盖；网页出口来自 Python 探测，浏览器代理规则不同时需另行核对。不自动修改任何配置。

退出码：`0` 表示已执行的检查没有已定义问题；`1` 表示有需核对项；`2` 表示检查不完整或操作失败；`130` 表示用户中止。这些不是平台账号安全等级。

## 网页资源

首次从源码使用网页需要准备静态资源：

```bash
npm --prefix web ci --ignore-scripts
npm --prefix web run build
```

构建产物位于 `src/ipcheck/static/`，由 Python 服务提供，不使用 CDN、在线字体、远程 JavaScript 或统计脚本。执行构建须遵循项目 AGENTS.md 的用户授权要求。资源缺失时 `ipcheck web` 会给出说明并以状态 2 退出。

## 检测与隐私边界

- 默认网络检查访问 ipify、icanhazip、AWS Check IP、ipwho.is，以及 `api.anthropic.com/cdn-cgi/trace` 和 `claude.ai/cdn-cgi/trace`。两个 Claude 同域名接口只接收匿名 HTTPS GET，不调用模型，不发送 API Key、Cookie 或登录凭证。各服务会看到对应请求的出口 IP；ipwho.is 会收到指定的观测 IP。
- `--reputation` 或网页勾选信誉查询后，额外联系 proxycheck.io 与 StopForumSpam；第三方配额或服务错误保留为未知。
- 所有外部查询使用 HTTPS、响应大小限制和超时。出口观测遵循当前进程/系统可识别的代理配置，不保证与其他应用或运行中会话的路径相同。
- IP 归属查询默认遵循代理；失败后仅对 ipwho.is 的指定公网 IP 查询尝试直连，并在报告记录 `lookup_route`。回退查询的仍是原先观测 IP，不替换出口观测、不修改 Clash 分流。直连时 ipwho.is 也能看到这次归属查询的直连来源 IP。
- Claude 探测固定官方 API/网页域名，用以识别当前进程的域名分流。自定义中转、进程/用户代理规则或已登录客户端可能采用其他路径；trace 被阻止或缺字段时保留为未知。Cloudflare `colo` 是服务节点位置，不用来推断用户出口时区。
- IPv6 分开显示“本机 IPv6 配置”“本机 IPv6 地址”“IPv6 出口探测”。macOS 配置通过 IPv4 默认路由定位网络服务，再读取 `networksetup -getinfo`；只对该服务明确返回 Off 时显示“已关闭”。接口检查只保留计数和接口名，区分公网、ULA 与链路本地地址，不输出原始 IP/MAC。VPN 默认接口无法映射或命令失败时保留未知，其他平台的配置检测暂标不支持。
- IPv6 出口探测并发查询 `api6.ipify.org` 与 `ipv6.icanhazip.com`，任一来源返回有效公网 IPv6 即记录可达及地址；部分成功时保留另一个来源的失败原因，全部失败时直接显示超时、DNS、TLS 等错误。两个来源均成功且 IP 不同时提示核对域名分流，不推断泄露。备用服务沿用同一路径，不增加强制直连。IPv6 出口探测遵循当前系统/进程代理；本机即使关闭 IPv6，仍可能经 IPv4 连接代理，由代理访问 IPv6 目标。探测失败不证明本机已关闭，成功也不等于泄露。Clash 的配置文件、运行配置、DNS AAAA 开关和节点实际 IPv6 能力是不同证据；工具不会自动读取其控制凭证、节点订阅或修改设置。DNS 配置不等于解析路径，首版没有主动 DNS 泄露服务。
- 默认只检查用户级 Claude 端点覆盖；不覆盖项目级、受管配置或运行中进程。只输出主机，不输出 URL 凭据、路径或查询参数。
- `--local` 只返回变量名、行号、配置存在性和身份比对数量。不会输出配置原文、邮箱、UUID、API Key 或 Token，不访问钥匙串明文、Cookie 内容和会话文本。
- 字体检查默认关闭，启用后只测试固定 8 种字体的渲染宽度，不生成指纹标识。中文语言和字体不作为账号风险分数。
- JSON 包含 IP、浏览器 UA、语言等环境信息；分享前仍应根据用途检查这些信息。
- 报告不保证账号安全、不预测封号，不自动修改代理、删除配置或重置身份。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
npm --prefix web run typecheck
npm --prefix web run lint
npm --prefix web test
```

测试只使用人工构造数据及短暂的本机随机端口，不调用外部检测服务。网页视觉与交互由用户人工检查；自动化视觉审查需另行明确要求。

设计见 [架构](docs/architecture.md)、[检测说明](docs/checks.md)；报告格式为 `schemas/report.schema.json`。
