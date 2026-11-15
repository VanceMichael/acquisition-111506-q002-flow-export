import test from 'node:test';
import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { emitPackets } from '../provider/source.mjs';

test('合作出口实际发送独立地址的v9数据报', async () => {
  const socket = createSocket('udp4');
  const received = [];
  const finished = new Promise(resolve => socket.on('message', (message, info) => {
    received.push({ message, info });
    if (received.length === 2) resolve();
  }));
  await new Promise(resolve => socket.bind(0, '127.0.0.1', resolve));
  try {
    await emitPackets(socket.address().port, { indexes: [0, 2] });
    await Promise.race([finished, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('未收到UDP资料')), 3000);
      timer.unref();
    })]);
    assert.equal(received[0].message.readUInt16BE(0), 9);
    assert.equal(new Set(received.map(packet => packet.info.address)).size, 2);
    assert.equal(received[0].message.readUInt32BE(16), 7);
  } finally { socket.close(); }
});
