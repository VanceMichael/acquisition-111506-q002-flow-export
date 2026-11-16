# 园区流量收件站

这个服务保存流观察的人工收件、历史版本和原始依据，并通过真实 UDP 套接字接收两台边缘设备的 NetFlow v9 导出。重复提交相同业务内容与依据返回原收件；内容变化形成历史版本，原始字节用内容摘要回查。合作来源运行在本机，具体交互见 `docs/source-contract.md`。

## 运行环境

需要 Node.js 22.22.1 至 22.x，使用内置模块，没有第三方依赖。依赖锁文件随代码保存；`npm ci --offline --ignore-scripts --no-audit --no-fund` 不会下载包。数据目录默认是 `var`，可用 `DATA_DIR` 指定；不可让两个进程同时写同一目录。HTTP 来源和收件服务默认只监听回环地址，不使用真实机构账号或外网数据。

## 开发与运行

```sh
npm ci --offline --ignore-scripts --no-audit --no-fund
npm run build
npm test
npm run demo
```

`npm start` 启动收件服务，HTTP 默认端口4310（`PORT`/`HOST`），同时在回环打开 NetFlow UDP 接收口，默认端口4312（`UDP_PORT`/`UDP_HOST`）。另一终端用 `npm run source` 启动来源端，默认端口4311，再向其 `POST /emit` 并传入本服务的 UDP 端口即可发出数据报。测试和演示使用系统分配的端口，结束时关闭服务并删除临时收件数据，不需要固定等待时间。

## 人工收件接口

`GET /health` 查看状态（含 UDP 接收口信息）；`POST /api/manual` 接收 `record` 和 `evidence`。业务内容需要 `flowId, exporter, bytes`，其中 `flowId` 是已有人工收件标识。每份依据包含来源 `source`、原始字节 `bytesBase64`，可选 `mediaType` 和需要核对的 `sha256`。`GET /api/records` 返回当前版本，`GET /api/history?key=...` 返回单个业务标识的历史，`GET /api/evidence/摘要` 返回原始字节。人工入口不推断自动采集是否完整。

## NetFlow v9 自动采集接口

UDP 收到的每个数据报先做无状态 RFC 3954 解析，再按“出口地址 + Source ID + 运行世代”解释。模板编号只在该有效域内缓存，两出口复用同号模板或设备重启后沿用原地址都不会串用布局；没有适用模板的数据进入有界等待区（TTL 与容量可查、到期/超限可查），绝不猜字段。重启依据结合序号、sysUptime（32 位回绕）与 unix_secs 区分确认与不确定。序号缺口、重复、重启按数据报维度统计，缺口不换算成业务流丢失条数。选项模板的采样声明只覆盖同世代同接口；实测计数、推算估计和未知采样状态在流记录中分开保存。

- `GET /api/netflow/overview`：UDP 计数、出口/流/数据报/模板/等待区总量与限制
- `GET /api/netflow/exporters`：每出口的世代、序号缺口、重复、重启、异常与等待数量
- `GET /api/netflow/flows`：结构化流记录，支持 `exporter`、`generation` 过滤；含 `measured`、`estimated`、`sampling`、`unknownFields`、`templateBasis`
- `GET /api/netflow/datagrams`：数据报元数据（头部、世代、缺口/重复/重启标记），支持同样过滤
- `GET /api/netflow/datagrams/{datagramId}/raw`：按记录对应的 SHA256 取回原始 UDP 字节
- `GET /api/netflow/templates`：按有效域隔离的模板与选项模板（含 revision）
- `GET /api/netflow/pending`：等待区条目与驱逐记录（`expired-ttl`、`evicted-capacity`）
- `GET /api/netflow/sampling`：按出口、世代、接口作用域保存的采样声明

原始数据报以 SHA256 内容寻址存于 blob 目录，状态变化写入 `netflow.jsonl`；服务重开后重放事件即可恢复全部自动采集状态。`fixtures/manual.json` 是人工收件样例，`fixtures/packets.json` 是两出口同模板号不同布局、选项采样、序号跳跃、重复及重启的 NetFlow 样例。`npm run demo` 实际启动本地服务与来源，经真实 UDP 完成端到端接收、解释与依据回查，不使用外部网络。

## 容器

```sh
docker build -t flow-export-intake .
docker run --rm --network none flow-export-intake npm test
docker run --rm --network none flow-export-intake npm run demo
```

镜像内容由 Dockerfile 的 SHA256 摘要固定；Node.js 22 主版本标签与 package.json 的 >=22.22.1 <23 兼容范围对应，验证环境可使用该范围内的补丁版本。构建需要本地已有该基础镜像；正式运行、测试和演示不安装系统包、不下载模型或数据。服务默认数据放在容器内临时目录，持久运行时可挂载单独卷。演示完整输出可在90秒内展示，不播放预先保存的日志。
