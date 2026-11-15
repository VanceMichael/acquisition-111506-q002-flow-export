
import { createSocket } from 'node:dgram';
import { readFile } from 'node:fs/promises';
import { serve, json, readBody } from './http.mjs';
const packets = JSON.parse(await readFile(new URL('../fixtures/packets.json', import.meta.url)));

export async function emitPackets(port, { indexes = packets.map((_, index) => index) } = {}) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('需要本地非特权UDP端口');
  for (const index of indexes) {
    const packet = packets[index];
    if (!packet) throw new Error('未知数据报');
    const socket = createSocket('udp4');
    try {
      await new Promise((resolve, reject) => {
        socket.once('error', reject);
        socket.bind(0, packet.sourceAddress, resolve);
      });
      await new Promise((resolve, reject) => socket.send(Buffer.from(packet.data, 'base64'), port, '127.0.0.1', error => error ? reject(error) : resolve()));
    } finally { socket.close(); }
  }
  return indexes.length;
}

export async function startProvider(options = {}) {
  return serve(async ({ request, response, url }) => {
    if (url.pathname === '/emit' && request.method === 'POST') {
      const body = JSON.parse((await readBody(request)).toString());
      return json(response, { sent: await emitPackets(body.port, { indexes: body.indexes }) });
    }
    if (url.pathname === '/format') return json(response, { protocol: 'NetFlow', version: 9, transport: 'udp4', packets: packets.length });
    return false;
  }, options);
}
