import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createCollector } from '../src/collector.mjs';
import {
  v9Header, templateFlowset, optionsTemplateFlowset, dataFlowset, datagram, LAYOUT_A, LAYOUT_B,
} from './helpers.mjs';

const fixtures = JSON.parse(await readFile(new URL('../fixtures/packets.json', import.meta.url)));
const load = index => Buffer.from(fixtures[index].data, 'base64');

async function runFixture(collector) {
  for (const packet of fixtures) {
    await collector.ingest(Buffer.from(packet.data, 'base64'), { address: packet.sourceAddress, sourcePort: 40000 });
  }
}

const header = (sequence, sysUpTime, unixSeconds = 1_000) =>
  v9Header({ count: 1, sysUpTime, unixSeconds, sequence, sourceId: 7 });

test('模板按出口地址隔离：两个出口复用编号256但布局不同，各自正确解释', async () => {
  const collector = createCollector(null);
  await runFixture(collector);
  const state = collector.snapshot();
  const west = state.flows.find(f => f.exporterKey.startsWith('127.0.0.2') && f.generation === 0);
  const east = state.flows.find(f => f.exporterKey.startsWith('127.0.0.3'));
  assert.equal(west.measured.inBytes, '9007199254741001');
  assert.equal(west.inputSnmp, 7);
  assert.equal(east.measured.inBytes, 100);
  assert.equal(east.inputSnmp, 8);
  // 布局 B 的源地址在第二个字段；若错按 A 的字段顺序解释会读成目的地址
  assert.equal(east.sourceIpv4, '10.0.0.3');
  assert.equal(east.destinationIpv4, '10.0.0.4');
});

test('一个出口的模板不能解释另一个出口的同编号数据', async () => {
  const collector = createCollector(null);
  // 出口 A 先定义 256（布局 A）
  await collector.ingest(
    datagram(header(1, 100, 1000), templateFlowset(256, LAYOUT_A)),
    { address: '127.0.0.20', sourcePort: 1 });
  // 出口 B 直接发 256 数据，其布局是 B；绝不能借用 A 的模板
  const recordB = [{ 12: 0x0a000004, 8: 0x0a000003, 10: 8, 1: 100n }];
  await collector.ingest(
    datagram(v9Header({ count: 1, sysUpTime: 100, unixSeconds: 1000, sequence: 1, sourceId: 7 }),
      dataFlowset(256, LAYOUT_B, recordB)),
    { address: '127.0.0.21', sourcePort: 1 });
  let state = collector.snapshot();
  assert.equal(state.flows.length, 0);
  assert.equal(state.pending.length, 1);
  assert.equal(state.pending[0].exporterKey, '127.0.0.21#src7');
  // B 自己的模板到达后按 B 布局解释
  await collector.ingest(
    datagram(v9Header({ count: 1, sysUpTime: 200, unixSeconds: 1000, sequence: 2, sourceId: 7 }),
      templateFlowset(256, LAYOUT_B)),
    { address: '127.0.0.21', sourcePort: 1 });
  state = collector.snapshot();
  assert.equal(state.pending.length, 0);
  const flow = state.flows[0];
  assert.equal(flow.sourceIpv4, '10.0.0.3');
  assert.equal(flow.destinationIpv4, '10.0.0.4');
  assert.equal(flow.measured.inBytes, 100);
  assert.equal(flow.inputSnmp, 8);
});

test('不同UDP源端口但同一出口地址不产生新身份', async () => {
  const collector = createCollector(null);
  const packet = datagram(header(1, 100), templateFlowset(256, LAYOUT_A));
  await collector.ingest(packet, { address: '127.0.0.9', sourcePort: 1111 });
  await collector.ingest(packet, { address: '127.0.0.9', sourcePort: 2222 });
  const state = collector.snapshot();
  assert.equal(state.exporters.length, 1);
  assert.equal(state.exporters[0].datagramCount, 2);
  assert.equal(state.templates.length, 1);
});

test('序号缺口按数据报计数，不声称业务流丢失条数', async () => {
  const collector = createCollector(null);
  await collector.ingest(load(0), { address: '127.0.0.2', sourcePort: 40000 }); // seq 1
  await collector.ingest(load(1), { address: '127.0.0.2', sourcePort: 40000 }); // seq 2
  await collector.ingest(load(3), { address: '127.0.0.2', sourcePort: 40000 }); // seq 4
  const exporter = collector.snapshot().exporters[0];
  assert.equal(exporter.gapCount, 1);
  const gap = collector.snapshot().datagrams.find(d => d.gap).gap;
  assert.equal(gap.missingDatagramCount, 1);
  assert.deepEqual(gap.missingDatagramSequences, [3]);
  assert.match(gap.note, /不能据此推算/);
});

test('完全重复的数据报标记重复且不重复产生流记录', async () => {
  const collector = createCollector(null);
  await runFixture(collector);
  const state = collector.snapshot();
  const exporter = state.exporters.find(e => e.exporterKey.startsWith('127.0.0.2'));
  assert.equal(exporter.duplicateCount, 1);
  const dupes = state.datagrams.filter(d => d.duplicate);
  assert.equal(dupes.length, 1);
  assert.equal(dupes[0].duplicateOf, state.datagrams.find(d => d.sequence === 4 && !d.duplicate).datagramId);
  // 重复数据报没有再解析 FlowSet：seq4 的流只出现一次
  const seq4Flows = state.flows.filter(f => f.sequence === 4 && f.generation === 0);
  assert.equal(seq4Flows.length, 1);
});

test('序号回退配合sysUptime重置判定为重启并开启新世代，迟到模板只在同世代有效', async () => {
  const collector = createCollector(null);
  await runFixture(collector);
  const state = collector.snapshot();
  const exporter = state.exporters.find(e => e.exporterKey.startsWith('127.0.0.2'));
  assert.equal(exporter.restartCount, 1);
  assert.equal(exporter.generations.length, 2);
  assert.equal(exporter.generations[1].basis, 'sequence-and-uptime-reset');
  assert.equal(exporter.generations[1].certainty, 'confirmed');
  // 世代1 的数据报先到、模板后到
  const restarted = state.flows.filter(f => f.generation === 1);
  assert.equal(restarted.length, 2);
  assert.equal(restarted[0].templateBasis, 'late-template');
  assert.equal(restarted[1].templateBasis, 'active-template');
  // 世代0 的模板不能解释世代1 的数据（布局不同，若沿用会把 100 读成 snmp）
  assert.equal(restarted[0].measured.inBytes, 100);
  assert.equal(restarted[0].inputSnmp, 8);
  // 世代1 的模板在世代0 模板之后定义，两个世代各有一份模板256
  const templates256 = state.templates.filter(t => t.templateId === 256 && t.exporterKey === exporter.exporterKey);
  assert.equal(templates256.length, 2);
  assert.deepEqual(templates256[0].fields.map(f => f.type), [8, 12, 1, 10]);
  assert.deepEqual(templates256[1].fields.map(f => f.type), [12, 8, 10, 1]);
});

test('只有sysUptime下降而序号仍前进时不切换世代，只记录异常', async () => {
  const collector = createCollector(null);
  await collector.ingest(
    datagram(header(1, 5000, 100), templateFlowset(256, LAYOUT_A)),
    { address: '127.0.0.5', sourcePort: 1 });
  await collector.ingest(
    datagram(header(2, 1000, 110), templateFlowset(256, LAYOUT_A)),
    { address: '127.0.0.5', sourcePort: 1 });
  const exporter = collector.snapshot().exporters[0];
  assert.equal(exporter.generations.length, 1);
  assert.equal(exporter.anomalies[0].anomaly, 'sysuptime-decreased-without-restart');
});

test('sysUptime的32位回绕用unix_secs佐证，不被误判为重启', async () => {
  const collector = createCollector(null);
  const wrapMs = 2 ** 32;
  // 两次墙钟间隔超过回绕周期：sysUptime 数值下降属于回绕
  const first = datagram(
    v9Header({ count: 1, sysUpTime: wrapMs - 10_000, unixSeconds: 1000, sequence: 10, sourceId: 7 }),
    templateFlowset(256, LAYOUT_A));
  const second = datagram(
    v9Header({ count: 1, sysUpTime: 5_000, unixSeconds: 1000 + wrapMs / 1000, sequence: 11, sourceId: 7 }),
    templateFlowset(256, LAYOUT_A));
  await collector.ingest(first, { address: '127.0.0.6', sourcePort: 1 });
  await collector.ingest(second, { address: '127.0.0.6', sourcePort: 1 });
  const exporter = collector.snapshot().exporters[0];
  assert.equal(exporter.generations.length, 1);
  assert.equal(exporter.anomalies[0].anomaly, 'uptime-32bit-wrap');
});

test('无模板数据进入有界等待区，模板到达后按同世代补解释，原始字节不猜字段', async () => {
  const collector = createCollector(null);
  // 先发数据，没有任何模板
  const data = datagram(header(1, 100), dataFlowset(256, LAYOUT_A, [{ 8: 0x0a000001, 12: 0x0a000002, 1: 5n, 10: 7 }]));
  await collector.ingest(data, { address: '127.0.0.7', sourcePort: 1 });
  let state = collector.snapshot();
  assert.equal(state.flows.length, 0);
  assert.equal(state.pending.length, 1);
  assert.equal(state.pending[0].status, 'waiting');
  // 再发模板
  await collector.ingest(datagram(header(2, 200), templateFlowset(256, LAYOUT_A)), { address: '127.0.0.7', sourcePort: 1 });
  state = collector.snapshot();
  assert.equal(state.pending.length, 0);
  assert.equal(state.flows.length, 1);
  assert.equal(state.flows[0].templateBasis, 'late-template');
  assert.equal(state.flows[0].measured.inBytes, 5);
});

test('等待区TTL到期后被驱逐并可查询，不会无限占用内存', async () => {
  let now = Date.parse('2026-01-01T00:00:00Z');
  const collector = createCollector(null, {
    clock: () => new Date(now),
    limits: { pendingTtlMs: 1000, maxPendingPerExporter: 1000, sweepIntervalMs: 0 },
  });
  const data = datagram(header(1, 100), dataFlowset(256, LAYOUT_A, [{ 8: 1, 12: 2, 1: 5n, 10: 7 }]));
  await collector.ingest(data, { address: '127.0.0.8', sourcePort: 1 });
  assert.equal(collector.snapshot().pending.length, 1);
  now += 1001;
  await collector.ingest(datagram(header(2, 200)), { address: '127.0.0.8', sourcePort: 1 });
  const state = collector.snapshot();
  assert.equal(state.pending.length, 0);
  assert.equal(state.evictions.length, 1);
  assert.equal(state.evictions[0].reason, 'expired-ttl');
  assert.equal(state.flows.length, 0); // 到期后模板到达也不会把它当正常数据
});

test('等待区按每出口容量裁剪，先入队者先被驱逐', async () => {
  const collector = createCollector(null, {
    limits: { pendingTtlMs: 10_000_000, maxPendingPerExporter: 2, sweepIntervalMs: 0 },
  });
  const make = sequence => datagram(header(sequence, sequence * 10),
    dataFlowset(256, LAYOUT_A, [{ 8: 1, 12: 2, 1: BigInt(sequence), 10: 7 }]));
  for (const sequence of [1, 2, 3]) {
    await collector.ingest(make(sequence), { address: '127.0.0.8', sourcePort: 1 });
  }
  const state = collector.snapshot();
  assert.equal(state.pending.length, 2);
  assert.equal(state.evictions.length, 1);
  assert.equal(state.evictions[0].reason, 'evicted-capacity');
  assert.deepEqual(state.pending.map(p => p.header.sequence), [2, 3]);
});

test('选项模板的采样声明只覆盖同世代同接口：适用才推算，未知保持unknown', async () => {
  const collector = createCollector(null);
  await runFixture(collector);
  const state = collector.snapshot();
  const gen0 = state.flows.find(f => f.generation === 0 && f.exporterKey.startsWith('127.0.0.2'));
  assert.equal(gen0.sampling.status, 'configured');
  assert.equal(gen0.sampling.interval, 100);
  assert.equal(gen0.sampling.scopeInterface, 7);
  // 采到的计数与推算值严格分开
  assert.equal(gen0.measured.inBytes, '9007199254741001');
  assert.equal(gen0.estimated.kind, 'extrapolated');
  assert.equal(gen0.estimated.inBytes, '900719925474100100');
  // 另一个出口接口8没有采样声明
  const east = state.flows.find(f => f.exporterKey.startsWith('127.0.0.3'));
  assert.equal(east.sampling.status, 'unknown');
  assert.match(east.sampling.reason, /采样声明/);
  assert.equal(east.estimated.kind, 'unavailable');
  assert.equal(east.estimated.inBytes, null);
  // 重启后新世代没有选项模板，采样状态回到 unknown，旧声明不跨世代沿用
  const gen1 = state.flows.find(f => f.generation === 1);
  assert.equal(gen1.sampling.status, 'unknown');
  assert.equal(state.samplingDeclarations.length, 1);
});

test('重启后同世代迟到的选项模板仍适用于同世代后续记录', async () => {
  const collector = createCollector(null);
  // 世代0：模板+选项
  await collector.ingest(datagram(header(1, 10), templateFlowset(256, LAYOUT_A)), { address: '127.0.0.10', sourcePort: 1 });
  await collector.ingest(datagram(header(2, 20),
    optionsTemplateFlowset(300, [{ type: 2, length: 4 }], [{ type: 34, length: 4 }]),
    dataFlowset(300, [{ type: 2, length: 4 }, { type: 34, length: 4 }], [{ 2: 7, 34: 100 }])),
    { address: '127.0.0.10', sourcePort: 1 });
  // 重启（序号回退+uptime重置），世代1先只来数据
  await collector.ingest(datagram(header(1, 5, 2000),
    dataFlowset(256, LAYOUT_A, [{ 8: 1, 12: 2, 1: 3n, 10: 7 }])), { address: '127.0.0.10', sourcePort: 1 });
  // 世代1 的模板迟到
  await collector.ingest(datagram(header(2, 15, 2000), templateFlowset(256, LAYOUT_A)), { address: '127.0.0.10', sourcePort: 1 });
  let flow = collector.snapshot().flows.find(f => f.generation === 1);
  assert.equal(flow.sampling.status, 'unknown'); // 此时世代1 还没有采样声明
  // 世代1 的采样声明迟到，只覆盖世代1
  await collector.ingest(datagram(header(3, 25, 2000),
    optionsTemplateFlowset(300, [{ type: 2, length: 4 }], [{ type: 34, length: 4 }]),
    dataFlowset(300, [{ type: 2, length: 4 }, { type: 34, length: 4 }], [{ 2: 7, 34: 10 }])),
    { address: '127.0.0.10', sourcePort: 1 });
  await collector.ingest(datagram(header(4, 35, 2000),
    dataFlowset(256, LAYOUT_A, [{ 8: 1, 12: 2, 1: 4n, 10: 7 }])), { address: '127.0.0.10', sourcePort: 1 });
  const state = collector.snapshot();
  const later = state.flows.find(f => f.sequence === 4);
  assert.equal(later.sampling.status, 'configured');
  assert.equal(later.sampling.interval, 10);
  assert.equal(later.estimated.inBytes, 40);
  assert.equal(state.samplingDeclarations.filter(d => d.generation === 1).length, 1);
});

test('未知字段原样保留在结构化记录中', async () => {
  const collector = createCollector(null);
  const fields = [...LAYOUT_B, { type: 444, length: 2 }];
  await collector.ingest(datagram(header(1, 10), templateFlowset(256, fields)), { address: '127.0.0.11', sourcePort: 1 });
  await collector.ingest(datagram(header(2, 20),
    dataFlowset(256, fields, [{ 12: 0x0a000002, 8: 0x0a000001, 10: 8, 1: 11n, 444: 0xabcd }])),
    { address: '127.0.0.11', sourcePort: 1 });
  const flow = collector.snapshot().flows[0];
  assert.deepEqual(flow.unknownFields, [{ type: 444, length: 2, rawHex: 'abcd' }]);
});

test('畸形数据报保留解析错误状态且不影响后续接收', async () => {
  const collector = createCollector(null);
  const result = await collector.ingest(Buffer.from([0, 9, 0, 1]), { address: '127.0.0.12', sourcePort: 1 });
  assert.equal(result.accepted, false);
  assert.match(result.parseError, /v9头部/);
  await collector.ingest(datagram(header(1, 10), templateFlowset(256, LAYOUT_A)), { address: '127.0.0.12', sourcePort: 1 });
  const state = collector.snapshot();
  assert.equal(state.datagrams[0].parseStatus, 'error');
  assert.equal(state.templates.length, 1);
});

test('32位序号回绕不被当成重启，世代保持不变', async () => {
  const collector = createCollector(null);
  await collector.ingest(
    datagram(v9Header({ count: 1, sysUpTime: 5000, unixSeconds: 100, sequence: 0xfffffffe, sourceId: 7 }),
      templateFlowset(256, LAYOUT_A)),
    { address: '127.0.0.14', sourcePort: 1 });
  await collector.ingest(
    datagram(v9Header({ count: 1, sysUpTime: 6000, unixSeconds: 101, sequence: 0xffffffff, sourceId: 7 }),
      templateFlowset(256, LAYOUT_A)),
    { address: '127.0.0.14', sourcePort: 1 });
  await collector.ingest(
    datagram(v9Header({ count: 1, sysUpTime: 7000, unixSeconds: 102, sequence: 0, sourceId: 7 }),
      templateFlowset(256, LAYOUT_A)),
    { address: '127.0.0.14', sourcePort: 1 });
  const exporter = collector.snapshot().exporters[0];
  assert.equal(exporter.generations.length, 1);
  assert.equal(exporter.gapCount, 0);
  assert.ok(exporter.anomalies.some(a => a.anomaly === 'sequence-32bit-wrap'));
});

test('序号回退且unix_secs为零无法佐证时，重启标记为uncertain但仍隔离世代', async () => {
  const collector = createCollector(null);
  await collector.ingest(
    datagram(v9Header({ count: 1, sysUpTime: 9000, unixSeconds: 0, sequence: 5, sourceId: 7 }),
      templateFlowset(256, LAYOUT_A)),
    { address: '127.0.0.15', sourcePort: 1 });
  await collector.ingest(
    datagram(v9Header({ count: 1, sysUpTime: 100, unixSeconds: 0, sequence: 1, sourceId: 7 }),
      templateFlowset(256, LAYOUT_A)),
    { address: '127.0.0.15', sourcePort: 1 });
  const exporter = collector.snapshot().exporters[0];
  assert.equal(exporter.generations.length, 2);
  assert.equal(exporter.generations[1].certainty, 'uncertain');
  const restarted = collector.snapshot().datagrams.find(d => d.restart);
  assert.equal(restarted.restart.certainty, 'uncertain');
});

test('同世代重新定义模板会提升revision，迟到模板依据可区分', async () => {
  const collector = createCollector(null);
  await collector.ingest(datagram(header(1, 10), templateFlowset(256, LAYOUT_A)), { address: '127.0.0.13', sourcePort: 1 });
  await collector.ingest(datagram(header(2, 20),
    dataFlowset(256, LAYOUT_A, [{ 8: 1, 12: 2, 1: 5n, 10: 7 }])), { address: '127.0.0.13', sourcePort: 1 });
  // 无模板编号 257 的数据先等待
  await collector.ingest(datagram(header(3, 30),
    dataFlowset(257, LAYOUT_B, [{ 12: 2, 8: 1, 10: 7, 1: 9n }])), { address: '127.0.0.13', sourcePort: 1 });
  await collector.ingest(datagram(header(4, 40), templateFlowset(257, LAYOUT_B)), { address: '127.0.0.13', sourcePort: 1 });
  const late = collector.snapshot().flows.find(f => f.templateId === 257);
  assert.equal(late.templateBasis, 'late-template');
  assert.equal(late.templateRevision, 0);
  assert.equal(late.measured.inBytes, 9);
});
