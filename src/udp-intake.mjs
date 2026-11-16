// 真实 UDP 接收口。数据报从这里进入收集器；解析失败、无模板等待等状态都由
// 收集器负责，socket 层只做收包、边界保护和生命周期管理。

import { createSocket } from 'node:dgram';

export async function startUdpIntake(collector, { port = 0, host = '127.0.0.1', maxDatagramBytes = 65535 } = {}) {
  const socket = createSocket({ type: 'udp4', recvBufferSize: 1 << 20 });
  const counters = { received: 0, accepted: 0, duplicates: 0, parseErrors: 0, oversized: 0 };
  const errors = [];

  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(port, host, resolve);
  });
  socket.setRecvBufferSize(1 << 20);

  socket.on('message', (message, info) => {
    counters.received += 1;
    if (message.length > maxDatagramBytes) {
      // UDP 数据报本身有长度上限；超过约定安全值的不进入解析，避免异常负载拖垮内存。
      counters.oversized += 1;
      errors.push({ at: new Date().toISOString(), reason: 'oversized-datagram', size: message.length, address: info.address });
      return;
    }
    // 收集器内部已经吃掉可预期的解析错误并保留原始字节；这里再兜一层防未知异常。
    Promise.resolve(collector.ingest(message, { address: info.address, sourcePort: info.port }))
      .then(result => {
        if (result.accepted) counters.accepted += 1;
        if (result.duplicate) counters.duplicates += 1;
        if (result.parseError) counters.parseErrors += 1;
      })
      .catch(error => {
        counters.parseErrors += 1;
        errors.push({ at: new Date().toISOString(), reason: error.message, address: info.address });
      });
  });

  socket.on('error', error => errors.push({ at: new Date().toISOString(), reason: error.message }));

  const address = socket.address();
  return {
    host: address.address,
    port: address.port,
    socket,
    counters,
    errors,
    close: () => new Promise(resolve => socket.close(resolve)),
  };
}
