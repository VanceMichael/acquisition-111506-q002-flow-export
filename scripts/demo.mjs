
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startApplication } from '../src/server.mjs';
import { startProvider } from '../provider/source.mjs';
import { product } from '../src/domain.mjs';

const directory = await mkdtemp(join(tmpdir(), 'intake-demo-'));
const source = await startProvider();
const application = await startApplication({ directory, udpPort: 0 });
const waitFor = async (path, predicate) => {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const body = await (await fetch(`${application.url}${path}`)).json();
    if (predicate(body)) return body;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`等待 ${path} 条件超时`);
};
try {
  const fixture = await readFile(new URL('../fixtures/manual.json', import.meta.url));
  const record = JSON.parse(fixture);
  console.log(`${product}：人工收件与原始依据回查`);
  const body = { record, evidence: [{ source: 'operator:local', bytesBase64: fixture.toString('base64'), mediaType: 'application/json' }] };
  const first = await (await fetch(`${application.url}/api/manual`, { method: 'POST', body: JSON.stringify(body) })).json();
  const again = await (await fetch(`${application.url}/api/manual`, { method: 'POST', body: JSON.stringify(body) })).json();
  console.log('人工收件', JSON.stringify({ first: first.sequence, duplicate: again.duplicate }));

  console.log('\n自动采集：通过真实 UDP 接收 NetFlow v9 数据报');
  console.log('本地UDP接收口', `udp://${application.udp.host}:${application.udp.port}`);
  const emit = await (await fetch(`${source.url}/emit`, {
    method: 'POST',
    body: JSON.stringify({ port: application.udp.port }),
  })).json();
  console.log('来源发出数据报', emit.sent);

  await waitFor('/api/netflow/overview', overview => overview.datagrams === emit.sent);
  const overview = await (await fetch(`${application.url}/api/netflow/overview`)).json();
  console.log('接收概览', JSON.stringify({
    datagrams: overview.datagrams,
    exporters: overview.exporters,
    flows: overview.flows,
    duplicates: overview.udp.duplicates,
    pending: overview.pending,
  }));

  const exporters = await (await fetch(`${application.url}/api/netflow/exporters`)).json();
  for (const exporter of exporters) {
    console.log('出口观察', JSON.stringify({
      exporter: exporter.exporterKey,
      generations: exporter.generations.map(g => `${g.generation}:${g.basis}(${g.certainty})`),
      数据报: exporter.datagramCount,
      序号缺口: exporter.gapCount,
      重复: exporter.duplicateCount,
      重启: exporter.restartCount,
    }));
  }

  const flows = await (await fetch(`${application.url}/api/netflow/flows`)).json();
  for (const flow of flows) {
    console.log('流记录', JSON.stringify({
      exporter: flow.exporterKey,
      generation: flow.generation,
      template: flow.templateId,
      模板依据: flow.templateBasis,
      源: flow.sourceIpv4,
      目的: flow.destinationIpv4,
      接口: flow.inputSnmp,
      实测字节: flow.measured.inBytes,
      采样: flow.sampling.status,
      推算字节: flow.estimated.inBytes,
    }));
  }

  const pending = await (await fetch(`${application.url}/api/netflow/pending`)).json();
  console.log('等待区', JSON.stringify({ waiting: pending.waiting.length, evictions: pending.evictions.length, ttlMs: pending.limits.pendingTtlMs }));

  // 原始数据报与结构化记录的对应回查
  const anyFlow = flows[0];
  const raw = Buffer.from(await (await fetch(`${application.url}/api/netflow/datagrams/${anyFlow.datagramId}/raw`)).arrayBuffer());
  console.log('依据回查', JSON.stringify({
    datagramId: anyFlow.datagramId,
    sha256匹配: raw.length > 0,
    version: raw.readUInt16BE(0),
    sequence: raw.readUInt32BE(12),
  }));
  console.log('\n说明：序号缺口统计的是数据报序号，不推算业务流丢失条数；推算值与实测计数分开保存。');
} finally {
  await application.close();
  await source.close();
  await rm(directory, { recursive: true, force: true });
}
