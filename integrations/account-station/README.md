# 账户站占位与空返检测开关联动

`empty-stream-guard-switch.patch` 是增量补丁，基于已部署的 Sub2API 0.2.23 账户站扩展，不能直接当成官方干净源码的完整补丁。服务器更新器中已保存包含原有补丁的完整 backend 和 frontend patch。

账户编辑页的“首字占位”旁增加“空返检测”。额外 Chat 空返保护只在进程启用账户站扩展、账户占位开启、账户空返检测明确开启时运行：

```json
{"stream_placeholder":{"enabled":true,"empty_stream_guard_enabled":true,"min_seconds":1,"max_seconds":5}}
```

字段缺失、值无效、关闭占位或关闭检测均不启用这层额外保护。AG 通道的两项开关都关闭，AG 自身继续负责占位、启动预算、空返和换号。没有针对 AG ID 的专门透传代码。官方原有拒答检测、错误分类和协议转换保持原实现。

原冲突是额外 `openAIChatEmptyStreamGuard` 无条件缓存空角色帧，导致 AG 占位直到正文到达才被放出。补丁让这个可选保护受账户开关控制。开启时仍能拦截无输出的角色帧加 DONE；关闭时复用现有 raw Chat 返回路径。

验证包括开关组合、缺失/非法字段、真正空返、传输错误、已输出后不重放、取消与缓冲上限，以及官方 unit 测试。Vue 类型检查和生产构建通过。生产真实链路通过 AG、账户站、心悦站分别测首帧和正文，不能把占位算成正文速度保证。

更新时必须备份并保留更新器原有 `account-placeholder.patch`、`adapter.patch`、`account_extension.py` 和安装状态；只更新账户站。重启后检查账户站及下游心悦站是否临时不可调度，确认健康后用原生 `recover-state` 恢复。不能直接清除真正失效账户的限制。
