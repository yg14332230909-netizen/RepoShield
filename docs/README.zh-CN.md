# RepoShield 文档地图

这个目录里的文档按主题拆分。新读者不需要从头读完所有文件，按下面路径看就够了。

## 先读这三篇

1. [根 README](../README.zh-CN.md)  
   了解 RepoShield 是什么、插在哪里、当前能做什么、边界是什么。

2. [真实 Agent 接入指南](REAL_AGENT_INTEGRATION.zh-CN.md)  
   面向第一次接触项目的人，解释如何通过 `base_url` 把真实 agent 接到 RepoShield Gateway。

3. [Gateway 指南](GATEWAY_GUIDE.zh-CN.md)  
   面向实现和调试，解释 Gateway 请求流、真实 upstream、响应转换和 streaming 边界。

## 按任务阅读

接入真实 agent：

- [真实 Agent 接入指南](REAL_AGENT_INTEGRATION.zh-CN.md)
- [Gateway 指南](GATEWAY_GUIDE.zh-CN.md)
- [Tool Parser Plugin 指南](TOOL_PARSER_PLUGIN_GUIDE.zh-CN.md)
- [Adapter 指南](ADAPTER_GUIDE.zh-CN.md)

理解安全控制链：

- [Sandbox 指南](SANDBOX_GUIDE.zh-CN.md)
- [Policy Pack 指南](POLICY_PACK_GUIDE.zh-CN.md)
- [测试用例说明](TEST_CASES.zh-CN.md)

跑 demo 或 bench：

- [第三阶段使用说明](THIRD_STAGE_USAGE.zh-CN.md)
- [Gateway Bench 指南](BENCH_GATEWAY_GUIDE.zh-CN.md)
- [Bench Report 指南](BENCH_REPORT_GUIDE.zh-CN.md)

看报告和可视化：

- [Studio 指南](STUDIO_GUIDE.zh-CN.md)
- [Bench Report 指南](BENCH_REPORT_GUIDE.zh-CN.md)

历史阶段资料：

- [第二阶段使用说明](SECOND_STAGE_USAGE.zh-CN.md)
- [第三阶段使用说明](THIRD_STAGE_USAGE.zh-CN.md)

## 建议重点维护

当前最推荐维护的是：

```text
README.zh-CN.md
docs/README.zh-CN.md
docs/REAL_AGENT_INTEGRATION.zh-CN.md
docs/GATEWAY_GUIDE.zh-CN.md
docs/TOOL_PARSER_PLUGIN_GUIDE.zh-CN.md
```

其他文档保留为专题说明或历史资料。后续建议继续把重复内容收敛到上述入口文档中。

## 一句话路线图

```text
先让别人看懂项目 -> 再让真实 agent 改 base_url 接入 -> 再补 streaming / sandbox / approval UI / agent 专用 adapter
```

