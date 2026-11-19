# AG 与3067的独立网络部署

AG 和3067分别使用独立网络命名空间。不能使用 `network_mode: container:agent2api`：AG 因 OOM 或其他原因重启后，3067会留在旧 namespace，公开端口可能无法到达仍在运行的网页进程。

本次生产沿用两者原有镜像、挂载、凭证和默认 bridge，AG 自己发布3065，3067自己发布3067到容器8080。3067增加 `ag-host:host-gateway`，设置 `AG_GATEWAY_URL=http://ag-host:3065`。两者均不设置CPU、内存、PID资源上限。完整生产配置包含私密环境文件引用，保存在服务器release目录，不提交公开仓库。

宿主防火墙默认丢弃 INPUT 时，还要允许3067经 docker0访问宿主AG映射端口。当前生产桥为172.17.0.0/16，宿主桥地址172.17.0.1，使用内部规则：

```sh
ufw allow in on docker0 from 172.17.0.0/16 to 172.17.0.1 port 3065 proto tcp comment ag-maintenance-gateway
```

其他机器必须先核实实际网桥和地址。此规则不新增公网入口。AG管理认证继续保留。

验收必须同时覆盖：外部3067网页、3067容器内AG健康和管理接口、AG重启期间3067网页连续可用，以及三家真实签到/余额任务和AG回执。仅在宿主机测HTTP200不够。

本次AG受控重启期间3067网页21次检查全部200，3067进程与网络namespace不变。补齐内部防火墙规则后，容器内AG健康、登录、inflight接口通过；Loomy、小熊、WPS自动签到及余额六类实际任务均成功，AG回执done、旧平台not_required。正常排队任务仍遵守原有优先级，不能把queued当作执行通过。
