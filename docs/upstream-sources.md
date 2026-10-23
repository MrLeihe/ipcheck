# 上游来源与修改记录

| 项目 | 固定调研提交 | 本项目吸收内容 |
| --- | --- | --- |
| https://github.com/stormzhang/ipcheck | 50018243a5699df10c6b46617f3fe4bd73b35dab | macOS 代理解析、端点/时区采集和本地摘要的设计思路 |
| https://github.com/yacuo/check-cc | 078e7baa1d2a08df28da3f25dacb90e687f4c79f | 浏览器 Intl/navigator 采样、字体宽度比较及信号模块化思路 |

## 具体修改

- platforms/system.py 的 parse_macos_proxy 参考 ipcheck 原解析方式，移除地址及凭据输出，只返回启用类型。
- checks/claude.py 重新实现用户端点读取、严格服务商域名匹配和来源冲突展示，不延用关键词包含分类或静态黑名单评级。
- checks/timezone.py 保留区分系统/CLI 的思路，IANA 名称和 UTC 偏移分别解释。
- checks/local.py 重新实现 opt-in 摘要，不复制上游整行 shell 输出、Cookie/钥匙串探测、账号清理建议或会话深扫。
- web/src/detection/collect.ts 改编 check-cc 的浏览器采集和 canvas 宽度比较；移除语言/字体的地区风险加权，限制字体清单并默认关闭。
- output/render.py 参考 ipcheck 的双列表格面板：双线外框、板块分隔、项目名/结果两列和结果配色。重新实现按中文显示宽度换行、窄屏单列、自适应列宽、脱敏后渲染及按结果数据展开字段；未复制风险结论和“IPv6 查询失败即已禁用”等判断。
- 网页 UI、报告结构、执行器、HTTPS 传输层、本地认证服务与测试为本项目新实现。
- 未沿用上游品牌页面、宣传内容、远程资源、历史水印检测或未经验证的“账号安全”结论。

ipcheck 根 LICENSE 为 Apache-2.0，但其 README、pyproject 元数据标注 MIT。本项目保留实际根 LICENSE 原文，并记录该差异，不把相关来源统一声明为 MIT。check-cc 根 LICENSE 为 MIT，保留作者声明及许可证原文。

两个来源的固定版本曾克隆用于只读调研，原 Git 历史与 .git 未嵌套放入本项目。后续更新应先固定新的上游版本，再定点移植并更新本记录。
