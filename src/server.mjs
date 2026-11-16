
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { openStore } from './store.mjs';
import { validateRecord, product } from './domain.mjs';
import { createCollector } from './collector.mjs';
import { startUdpIntake } from './udp-intake.mjs';

export async function readJson(request, limit = 8 * 1024 * 1024) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > limit) throw Object.assign(new Error('收件超过大小限制'), { status: 413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('请求不是有效JSON'), { status: 400 }); }
}

export function sendJson(response, status, body) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(body));
}

export async function startApplication({
  directory,
  port = 0,
  host = '127.0.0.1',
  udpPort = null,
  udpHost = '127.0.0.1',
  limits,
}) {
  const store = await openStore(directory);
  const collector = createCollector(store, { limits });
  await collector.replay(await store.readNetflow());
  let udp = null;
  if (udpPort !== null) {
    udp = await startUdpIntake(collector, { port: udpPort, host: udpHost });
    collector.startSweeper();
  }

  const selectByExporter = (items, params) => {
    const exporter = params.get('exporter');
    const generation = params.get('generation');
    return items.filter(item => {
      if (exporter && item.exporterKey !== exporter) return false;
      if (generation !== null && item.generation !== Number(generation)) return false;
      return true;
    });
  };

  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://localhost');
      if (request.method === 'GET' && url.pathname === '/health') {
        return sendJson(response, 200, { product, status: 'ok', udp: udp ? { host: udp.host, port: udp.port } : null });
      }
      if (request.method === 'POST' && url.pathname === '/api/manual') {
        const input = await readJson(request);
        const { key, record } = validateRecord(input.record);
        const receipt = await store.accept(key, record, input.evidence);
        return sendJson(response, receipt.duplicate ? 200 : 201, receipt);
      }
      if (request.method === 'GET' && url.pathname === '/api/records') return sendJson(response, 200, store.list());
      if (request.method === 'GET' && url.pathname === '/api/history') return sendJson(response, 200, store.history(url.searchParams.get('key')));
      if (request.method === 'GET' && url.pathname.startsWith('/api/evidence/')) {
        const bytes = await store.evidence(url.pathname.slice('/api/evidence/'.length));
        response.writeHead(200, { 'content-type': 'application/octet-stream' });
        return response.end(bytes);
      }

      // ---- NetFlow v9 自动采集查询接口 ----
      if (request.method === 'GET' && url.pathname === '/api/netflow/overview') {
        const state = collector.snapshot();
        return sendJson(response, 200, {
          product,
          udp: udp ? { host: udp.host, port: udp.port, ...udp.counters, recentErrors: udp.errors.slice(-20) } : null,
          limits: collector.limits,
          exporters: state.exporters.length,
          flows: state.flows.length,
          datagrams: state.datagrams.length,
          templates: state.templates.length,
          pending: state.pending.length,
          evictions: state.evictions.length,
        });
      }
      if (request.method === 'GET' && url.pathname === '/api/netflow/exporters') {
        return sendJson(response, 200, collector.snapshot().exporters);
      }
      if (request.method === 'GET' && url.pathname === '/api/netflow/flows') {
        return sendJson(response, 200, selectByExporter(collector.snapshot().flows, url.searchParams));
      }
      if (request.method === 'GET' && url.pathname === '/api/netflow/datagrams') {
        return sendJson(response, 200, selectByExporter(collector.snapshot().datagrams, url.searchParams));
      }
      const rawMatch = /^\/api\/netflow\/datagrams\/([^/]+)\/raw$/.exec(url.pathname);
      if (request.method === 'GET' && rawMatch) {
        const datagram = collector.snapshot().datagrams.find(item => item.datagramId === rawMatch[1]);
        if (!datagram) return sendJson(response, 404, { error: '数据报不存在' });
        const bytes = await store.evidence(datagram.sha256);
        response.writeHead(200, {
          'content-type': 'application/octet-stream',
          'x-datagram-id': datagram.datagramId,
          'x-datagram-sha256': datagram.sha256,
        });
        return response.end(bytes);
      }
      if (request.method === 'GET' && url.pathname === '/api/netflow/templates') {
        return sendJson(response, 200, collector.snapshot().templates);
      }
      if (request.method === 'GET' && url.pathname === '/api/netflow/pending') {
        const state = collector.snapshot();
        return sendJson(response, 200, {
          limits: collector.limits,
          waiting: state.pending,
          evictions: state.evictions,
        });
      }
      if (request.method === 'GET' && url.pathname === '/api/netflow/sampling') {
        return sendJson(response, 200, collector.snapshot().samplingDeclarations);
      }

      sendJson(response, 404, { error: '入口不存在' });
    } catch (error) {
      const status = error.status ?? (error.code === 'ENOENT' ? 404 : 500);
      sendJson(response, status, { error: status === 500 ? '收件服务内部错误' : error.message });
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  return {
    store, collector, udp,
    server,
    url: `http://${host}:${server.address().port}`,
    async close() {
      if (udp) await udp.close();
      await collector.flush();
      await new Promise(resolve => server.close(resolve));
      await store.flush();
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const application = await startApplication({
    directory: process.env.DATA_DIR ?? './var',
    port: Number(process.env.PORT ?? 4310),
    host: process.env.HOST ?? '127.0.0.1',
    udpPort: process.env.UDP_PORT ? Number(process.env.UDP_PORT) : 4312,
    udpHost: process.env.UDP_HOST ?? '127.0.0.1',
  });
  console.log(JSON.stringify({
    product,
    url: application.url,
    udp: application.udp ? { host: application.udp.host, port: application.udp.port } : null,
  }));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => application.close().then(() => process.exit(0)));
}
