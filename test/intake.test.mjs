import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSocket } from 'node:dgram';
import { startApplication } from '../src/server.mjs';
import { emitPackets } from '../provider/source.mjs';
import { startUdpIntake } from '../src/udp-intake.mjs';
import { createCollector } from '../src/collector.mjs';
import { createHash } from 'node:crypto';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const getJson = async (base, path) => (await fetch(`${base}${path}`)).json();

async function emitAll(app) {
  await emitPackets(app.udp.port);
  // UDP 处理是异步串行的，轮询到全部9个数据报被接收
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const overview = await getJson(app.url, '/api/netflow/overview');
    if (overview.datagrams === 9) return overview;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('UDP 数据报未在限定时间内全部接收');
}

test('真实UDP入口接收合作来源数据报，原始字节与结构化流记录可互相回查', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'intake-e2e-'));
  const app = await startApplication({ directory, udpPort: 0 });
  try {
    await emitAll(app);
    const overview = await getJson(app.url, '/api/netflow/overview');
    assert.equal(overview.udp.received, 9);
    assert.equal(overview.udp.accepted, 9);
    assert.equal(overview.udp.duplicates, 1);
    assert.equal(overview.exporters, 2);

    const flows = await getJson(app.url, '/api/netflow/flows');
    const west = flows.find(f => f.exporterKey.startsWith('127.0.0.2') && f.generation === 0);
    // 结构化记录引用数据报摘要，原始字节按摘要取回且逐字节一致
    const datagrams = await getJson(app.url, '/api/netflow/datagrams');
    const source = datagrams.find(d => d.datagramId === west.datagramId);
    assert.equal(source.sha256, west.datagramSha256);
    const rawResponse = await fetch(`${app.url}/api/netflow/datagrams/${west.datagramId}/raw`);
    assert.equal(rawResponse.status, 200);
    const raw = Buffer.from(await rawResponse.arrayBuffer());
    assert.equal(sha256(raw), west.datagramSha256);
    assert.equal(raw.readUInt16BE(0), 9);
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('出口、世代、序号观察与采样状态通过HTTP可查询，缺口不换算成流丢失', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'intake-obs-'));
  const app = await startApplication({ directory, udpPort: 0 });
  try {
    await emitAll(app);
    const exporters = await getJson(app.url, '/api/netflow/exporters');
    const west = exporters.find(e => e.exporterKey.startsWith('127.0.0.2'));
    const east = exporters.find(e => e.exporterKey.startsWith('127.0.0.3'));
    assert.equal(west.generations.length, 2);
    assert.equal(west.restartCount, 1);
    assert.equal(west.gapCount, 1);
    assert.equal(west.duplicateCount, 1);
    assert.equal(east.generations.length, 1);

    const datagrams = await getJson(app.url, '/api/netflow/datagrams');
    const gap = datagrams.find(d => d.gap);
    assert.equal(gap.gap.missingDatagramCount, 1);
    assert.match(gap.gap.note, /不能据此推算/);
    const restart = datagrams.find(d => d.restart);
    assert.equal(restart.restart.certainty, 'confirmed');

    const sampling = await getJson(app.url, '/api/netflow/sampling');
    assert.equal(sampling.length, 1);
    assert.equal(sampling[0].scopeInterface, 7);
    assert.equal(sampling[0].interval, 100);

    const flows = await getJson(app.url, '/api/netflow/flows');
    const sampled = flows.find(f => f.sampling.status === 'configured');
    const unknown = flows.filter(f => f.sampling.status === 'unknown');
    assert.ok(sampled.estimated.kind === 'extrapolated');
    assert.ok(unknown.length >= 3);
    assert.ok(unknown.every(f => f.estimated.inBytes === null));

    const templates = await getJson(app.url, '/api/netflow/templates');
    // 两个出口各自的256模板 + 两个世代 + 一个选项模板
    assert.ok(templates.some(t => t.exporterKey.startsWith('127.0.0.3') && t.templateId === 256));
    assert.equal(templates.filter(t => t.templateId === 256).length, 3);
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('无模板数据先等待、迟到模板补解释，等待区状态可查询且最终清空', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'intake-pending-'));
  const app = await startApplication({ directory, udpPort: 0 });
  try {
    // 先建立世代0 的模板与序号上下文，再发重启后的首包（序号回退、新世代尚无模板）
    await emitPackets(app.udp.port, { indexes: [0, 3, 6] });
    await new Promise(resolve => setTimeout(resolve, 200));
    let pending = await getJson(app.url, '/api/netflow/pending');
    assert.equal(pending.waiting.length, 1);
    assert.equal(pending.waiting[0].generation, 1);
    assert.equal(pending.limits.maxPendingPerExporter, 1000);
    // 世代0 的流正常解释，世代1 的数据没有被旧模板误读
    const flowsBefore = await getJson(app.url, '/api/netflow/flows');
    assert.equal(flowsBefore.filter(f => f.generation === 1).length, 0);
    // 再发同世代模板（索引7）和后续数据（索引8）
    await emitPackets(app.udp.port, { indexes: [7, 8] });
    for (let attempt = 0; attempt < 50; attempt += 1) {
      pending = await getJson(app.url, '/api/netflow/pending');
      if (pending.waiting.length === 0) break;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(pending.waiting.length, 0);
    const flows = await getJson(app.url, '/api/netflow/flows');
    const late = flows.find(f => f.templateBasis === 'late-template');
    assert.ok(late);
    assert.equal(late.generation, 1);
    assert.equal(late.measured.inBytes, 100);
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('重启后重开服务：事件重放恢复世代、模板、流与采样状态，blob仍可取回', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'intake-replay-'));
  let flowIdsBefore;
  const first = await startApplication({ directory, udpPort: 0 });
  try {
    await emitAll(first);
    flowIdsBefore = (await getJson(first.url, '/api/netflow/flows')).map(f => f.flowId).sort();
    assert.equal(flowIdsBefore.length, 4);
  } finally {
    await first.close();
  }
  // 新进程、新收集器，只从磁盘事件与 blob 重建
  const reopened = await startApplication({ directory, udpPort: 0 });
  try {
    const exporters = await getJson(reopened.url, '/api/netflow/exporters');
    const west = exporters.find(e => e.exporterKey.startsWith('127.0.0.2'));
    assert.equal(west.generations.length, 2);
    assert.equal(west.restartCount, 1);
    assert.equal(west.duplicateCount, 1);
    assert.equal(west.gapCount, 1);
    const flows = await getJson(reopened.url, '/api/netflow/flows');
    assert.deepEqual(flows.map(f => f.flowId).sort(), flowIdsBefore);
    const sampling = await getJson(reopened.url, '/api/netflow/sampling');
    assert.equal(sampling[0].interval, 100);
    const datagrams = await getJson(reopened.url, '/api/netflow/datagrams');
    const anyDatagram = datagrams[0];
    const raw = Buffer.from(await (await fetch(`${reopened.url}/api/netflow/datagrams/${anyDatagram.datagramId}/raw`)).arrayBuffer());
    assert.equal(sha256(raw), anyDatagram.sha256);
  } finally {
    await reopened.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('UDP层对畸形负载记录解析错误且不崩溃，人工收件接口保持可用', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'intake-udp-'));
  const collector = createCollector(null);
  const udp = await startUdpIntake(collector, { port: 0 });
  const sender = createSocket('udp4');
  try {
    await new Promise(resolve => sender.bind(0, '127.0.0.1', resolve));
    await new Promise((resolve, reject) =>
      sender.send(Buffer.from([0, 9, 0, 1]), udp.port, '127.0.0.1', error => error ? reject(error) : resolve()));
    for (let attempt = 0; attempt < 30; attempt += 1) {
      if (udp.counters.parseErrors === 1) break;
      await new Promise(resolve => setTimeout(resolve, 30));
    }
    assert.equal(udp.counters.received, 1);
    assert.equal(udp.counters.parseErrors, 1);
    assert.equal(collector.snapshot().datagrams[0].parseStatus, 'error');

    const manual = JSON.parse(await readFile(new URL('../fixtures/manual.json', import.meta.url)));
    const app = await startApplication({ directory });
    try {
      const response = await fetch(`${app.url}/api/manual`, {
        method: 'POST',
        body: JSON.stringify({ record: manual, evidence: [{ source: 'operator:test', bytesBase64: Buffer.from('x').toString('base64') }] }),
      });
      assert.equal(response.status, 201);
      assert.equal((await getJson(app.url, '/api/records')).length, 1);
    } finally {
      await app.close();
    }
  } finally {
    sender.close();
    await udp.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('查询接口支持按出口与世代过滤', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'intake-filter-'));
  const app = await startApplication({ directory, udpPort: 0 });
  try {
    await emitAll(app);
    const exporterKey = '127.0.0.2#src7';
    const flows = await getJson(app.url, `/api/netflow/flows?exporter=${encodeURIComponent(exporterKey)}&generation=1`);
    assert.ok(flows.length >= 1);
    assert.ok(flows.every(f => f.exporterKey === exporterKey && f.generation === 1));
    const datagrams = await getJson(app.url, `/api/netflow/datagrams?exporter=${encodeURIComponent(exporterKey)}`);
    assert.ok(datagrams.every(d => d.exporterKey === exporterKey));
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('HTTP边界：未开UDP时health与overview仍可用，未知数据报返回404', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'intake-http-'));
  const app = await startApplication({ directory }); // 不传 udpPort
  try {
    const health = await (await fetch(`${app.url}/health`)).json();
    assert.equal(health.status, 'ok');
    assert.equal(health.udp, null);
    const overview = await getJson(app.url, '/api/netflow/overview');
    assert.equal(overview.udp, null);
    assert.equal(overview.flows, 0);
    const missing = await fetch(`${app.url}/api/netflow/datagrams/nope/raw`);
    assert.equal(missing.status, 404);
    assert.equal((await fetch(`${app.url}/api/netflow/flows`)).status, 200);
    assert.equal((await fetch(`${app.url}/no-such-route`)).status, 404);
  } finally {
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});
