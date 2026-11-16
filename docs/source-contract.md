# 园区流量收件站：合作来源契约

来源是实际UDP数据报，不是逐条JSON流。`POST /emit`接收`{"port":本地接收端口}`，向回环地址发出有限一组NetFlow v9数据报；可选`indexes`指定从样例序列的哪些位置发出，以便调整观察次序。这是本地导出设备的控制口，不是自动采集的数据入口；不直接读取packets.json代替UDP接收。默认使用127.0.0.2及127.0.0.3表示两个独立出口，使用不同UDP源端口不代表不同导出源。

支持RFC3954的20字节v9头、Template FlowSet 0、Options Template FlowSet 1和编号大于255的Data FlowSet。字段至少覆盖IN_BYTES(1)的8字节计数、IPV4_SRC_ADDR(8)、IPV4_DST_ADDR(12)、INPUT_SNMP(10)、SAMPLING_INTERVAL(34)。模板字段长度由模板指定，网络字节序，FlowSet有4字节对齐填充。选项模板的scope和option长度以字节表示，样例按Interface作用域给出采样间隔。保留不认识字段的类型、长度及字节，不必实现全部字段词典。

缓存有效域至少区分实际出口地址、Source ID和可解释的设备运行世代。协议不保证Data先于Template到达；不知道布局的字节不能推测成流记录。有限隔离的时长或容量可以由实现选择，但到期/超限状态需要可查询。sysUptime为32位毫秒值，会回绕；结合unix_secs、序号等来源依据区分可判定重启和不能确定的情况，不能只按数值下降切换。序号按导出包递增，不是流记录总数；重发/乱序不自动证明漏流数量。提供两出口同模板号不同布局、选项采样、序号跳跃、重复及重启的基础样例；维护者可调索引组织更多边界。大于安全整数的计数保存为十进制字符串，样本数量不等于总体数量。

## 收件端解释规则（自动接入实现）

收件端在 `src/udp-intake.mjs` 打开真实 UDP 套接字，解析与状态分别在 `src/netflow9.mjs`（无状态解析）和 `src/collector.mjs`（世代、模板、采样、序号状态机）中实现。关键规则：

- **出口身份**：数据报来源 IP 与头部 Source ID 组成导出源键；不同 UDP 源端口不产生新身份。模板、采样声明、序号观察全部按该身份隔离，两个出口复用同一模板编号也不会串用布局。
- **运行世代**：首个数据报开启世代；序号回退且 sysUptime 同步重置、unix_secs 又无法用 32 位回绕解释时判定重启并开启新世代，unix_secs 缺失时标记 `uncertain`。只有 sysUptime 下降而序号继续前进时不切换世代，记录 `sysuptime-decreased-without-restart`；墙钟跨度达到约 49.7 天回绕周期的记 `uptime-32bit-wrap`。模板只在“出口 + Source ID + 世代”内有效，世代切换后旧模板不解释新数据。
- **迟到模板**：没有适用模板的 Data FlowSet 连同原始字节进入有界等待区（默认每出口 1000 条、TTL 5 分钟，可通过 `limits` 调整），同世代模板到达后补解释并标注 `templateBasis=late-template`；TTL 到期记 `expired-ttl`、超容量按 FIFO 记 `evicted-capacity`，驱逐记录可在 `/api/netflow/pending` 查询，被驱逐数据不会在模板到达后冒充正常数据。
- **采样**：选项模板的采样声明按“出口 + 世代 + scope 接口”保存，只适用于同世代且 INPUT_SNMP 命中该接口的流。流记录里 `measured.inBytes` 是采到的原始计数，`estimated.inBytes` 是按 SAMPLING_INTERVAL 推算的总体估计（`kind=extrapolated`），没有适用声明时 `sampling.status=unknown`、推算值为 `null`，三类状态不混写；超过安全整数的推算值同样保存为十进制字符串。
- **序号观察**：按出口维护数据报序号，缺口事件给出缺失的序号区间与数据报条数，并明确声明不能据此推算业务流丢失数量；完全相同的字节重复（同一序号、同一摘要）标记重复且不重复解析 FlowSet，同序号不同字节记 `sequence-number-reused`。
- **原始依据对应**：每个数据报按 SHA256 内容寻址存入 blob 目录，结构化流记录携带 `datagramId` 与 `datagramSha256`，可经 `/api/netflow/datagrams/{id}/raw` 取回原始字节；所有状态变化写入 `netflow.jsonl` 事件日志，重开服务重放即可恢复世代、模板、采样、流与等待区状态。
- **查询接口**：`GET /api/netflow/overview|exporters|flows|datagrams|templates|pending|sampling`，flows 与 datagrams 支持 `exporter`、`generation` 查询参数。

## 来源与支持范围

格式参考：`https://www.rfc-editor.org/rfc/rfc3954`。这里运行的是只含虚构资料的本地合作端，不是公网生产服务；只需支持本文明确给出的范围。来源实现和样例可以阅读，自动接入应使用声明的交互入口，不把服务内部对象或预先写好的采集结论当作数据来源。原始依据、结构化内容和完整性状态应能在收件端回查；新增自动接口的名称与内部设计由开发者决定。
