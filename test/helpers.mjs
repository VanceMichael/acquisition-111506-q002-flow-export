// 测试用 NetFlow v9 数据报构造器：只用于测试，生产代码不依赖它解释数据。

export function v9Header({ count, sysUpTime, unixSeconds, sequence, sourceId }) {
  const buffer = Buffer.alloc(20);
  buffer.writeUInt16BE(9, 0);
  buffer.writeUInt16BE(count, 2);
  buffer.writeUInt32BE(sysUpTime >>> 0, 4);
  buffer.writeUInt32BE(unixSeconds >>> 0, 8);
  buffer.writeUInt32BE(sequence >>> 0, 12);
  buffer.writeUInt32BE(sourceId >>> 0, 16);
  return buffer;
}

export function templateFlowset(templateId, fields) {
  const body = Buffer.alloc(4 + fields.length * 4);
  body.writeUInt16BE(templateId, 0);
  body.writeUInt16BE(fields.length, 2);
  fields.forEach((field, index) => {
    body.writeUInt16BE(field.type, 4 + index * 4);
    body.writeUInt16BE(field.length, 6 + index * 4);
  });
  return withFlowsetHeader(0, body);
}

export function optionsTemplateFlowset(templateId, scopeFields, optionFields) {
  const all = [...scopeFields, ...optionFields];
  const body = Buffer.alloc(6 + all.length * 4);
  body.writeUInt16BE(templateId, 0);
  body.writeUInt16BE(scopeFields.length * 4, 2);
  body.writeUInt16BE(optionFields.length * 4, 4);
  all.forEach((field, index) => {
    body.writeUInt16BE(field.type, 6 + index * 4);
    body.writeUInt16BE(field.length, 8 + index * 4);
  });
  return withFlowsetHeader(1, body);
}

function withFlowsetHeader(id, body) {
  const header = Buffer.alloc(4);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(body.length + 4, 2);
  return Buffer.concat([header, body]);
}

function pad4(buffer) {
  const remainder = buffer.length % 4;
  return remainder === 0 ? buffer : Buffer.concat([buffer, Buffer.alloc(4 - remainder)]);
}

export function dataFlowset(templateId, fields, records) {
  const recordLength = fields.reduce((total, field) => total + field.length, 0);
  const body = Buffer.alloc(records.length * recordLength);
  records.forEach((record, row) => {
    let cursor = row * recordLength;
    fields.forEach(field => {
      const value = record[field.type];
      if (field.length === 4 && field.type !== 1) body.writeUInt32BE(value >>> 0, cursor);
      else if (field.length === 4 && field.type === 1) body.writeUInt32BE(value, cursor);
      else if (field.length === 8) body.writeBigUInt64BE(typeof value === 'bigint' ? value : BigInt(value), cursor);
      else if (field.length === 2) body.writeUInt16BE(value, cursor);
      else if (field.length === 1) body.writeUInt8(value, cursor);
      else throw new Error(`测试构造器不支持字段长度${field.length}`);
      cursor += field.length;
    });
  });
  return withFlowsetHeader(templateId, pad4(body));
}

export function ipv4(text) {
  return Buffer.from(text.split('.').map(Number));
}

export function datagram(header, ...flowsets) {
  return Buffer.concat([header, ...flowsets]);
}

// 常用模板布局
export const LAYOUT_A = [
  { type: 8, length: 4 },   // IPV4_SRC_ADDR
  { type: 12, length: 4 },  // IPV4_DST_ADDR
  { type: 1, length: 8 },   // IN_BYTES
  { type: 10, length: 4 },  // INPUT_SNMP
];
export const LAYOUT_B = [
  { type: 12, length: 4 },
  { type: 8, length: 4 },
  { type: 10, length: 4 },
  { type: 1, length: 8 },
];
