// RFC 3954 NetFlow v9 纯解析模块：不做任何状态缓存，只负责把数据报字节解释成
// 头部、FlowSet、模板定义与结构化字段。没有模板时绝不猜测数据布局。

export const NETFLOW_VERSION = 9;
export const HEADER_LENGTH = 20;
export const TEMPLATE_FLOWSET_ID = 0;
export const OPTIONS_TEMPLATE_FLOWSET_ID = 1;
export const MIN_DATA_FLOWSET_ID = 256;
export const UPTIME_WRAP = 2 ** 32;
export const SEQUENCE_WRAP = 2 ** 32;

// 本收件站认识的字段词典；不认识的字段保留类型、长度与原始字节。
export const FIELD_DICTIONARY = {
  1: { name: 'IN_BYTES', kind: 'counter' },
  2: { name: 'IF_INDEX', kind: 'index' },
  8: { name: 'IPV4_SRC_ADDR', kind: 'ipv4' },
  10: { name: 'INPUT_SNMP', kind: 'index' },
  12: { name: 'IPV4_DST_ADDR', kind: 'ipv4' },
  34: { name: 'SAMPLING_INTERVAL', kind: 'number' },
};

export class NetFlowParseError extends Error {
  constructor(message, offset) {
    super(message);
    this.name = 'NetFlowParseError';
    this.offset = offset;
  }
}

function readUnsigned(buffer, offset, length) {
  switch (length) {
    case 1: return buffer.readUInt8(offset);
    case 2: return buffer.readUInt16BE(offset);
    case 4: return buffer.readUInt32BE(offset);
    case 8: {
      const value = buffer.readBigUInt64BE(offset);
      return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
    }
    default:
      return buffer.subarray(offset, offset + length).toString('hex');
  }
}

function decodeIpv4(buffer, offset, length) {
  if (length === 4) return Array.from(buffer.subarray(offset, offset + 4)).join('.');
  return buffer.subarray(offset, offset + length).toString('hex');
}

// 按模板声明的字段长度解释一条记录；模板里每个字段多长就读多长，不自行假设。
export function decodeFields(templateFields, buffer, offset) {
  const fields = [];
  let cursor = offset;
  for (const definition of templateFields) {
    const { type, length } = definition;
    if (cursor + length > offset + buffer.length) {
      throw new NetFlowParseError(`字段类型${type}超出记录边界`, cursor);
    }
    const known = FIELD_DICTIONARY[type];
    const rawHex = buffer.subarray(cursor, cursor + length).toString('hex');
    let value;
    if (known?.kind === 'ipv4') value = decodeIpv4(buffer, cursor, length);
    else value = readUnsigned(buffer, cursor, length);
    fields.push({ type, name: known?.name ?? null, length, value, rawHex });
    cursor += length;
  }
  return { fields, recordLength: cursor - offset };
}

export function templateRecordLength(templateFields) {
  return templateFields.reduce((total, field) => total + field.length, 0);
}

// 用模板定义切分一个 Data FlowSet 的负载，末尾 4 字节对齐填充作为 padding 保留。
// buffer 为数据报或 FlowSet 本体；dataOffset/end 均为相对该 buffer 的绝对偏移。
export function decodeDataFlowset(template, flowset, buffer = flowset.dataBuffer) {
  const recordLength = templateRecordLength(template.fields);
  if (recordLength === 0) throw new NetFlowParseError('模板没有任何字段，无法解释数据');
  const records = [];
  let cursor = flowset.dataOffset;
  const end = flowset.dataOffset + (flowset.length - 4);
  while (cursor + recordLength <= end) {
    const { fields } = decodeFields(template.fields, buffer, cursor);
    records.push({ recordIndex: records.length, fields });
    cursor += recordLength;
  }
  const paddingLength = end - cursor;
  if (paddingLength >= recordLength) {
    throw new NetFlowParseError('Data FlowSet 剩余字节无法按模板对齐', cursor);
  }
  return { records, paddingLength };
}

function parseTemplateFlowset(buffer, flowset) {
  const templates = [];
  let cursor = flowset.offset + 4;
  const end = flowset.offset + flowset.length;
  while (cursor < end) {
    if (end - cursor < 4) break; // FlowSet 尾部对齐填充
    const templateId = buffer.readUInt16BE(cursor);
    const fieldCount = buffer.readUInt16BE(cursor + 2);
    if (templateId < MIN_DATA_FLOWSET_ID) {
      throw new NetFlowParseError(`模板编号${templateId}不在数据编号范围`, cursor);
    }
    const fields = [];
    for (let index = 0; index < fieldCount; index += 1) {
      const fieldCursor = cursor + 4 + index * 4;
      if (fieldCursor + 4 > end) throw new NetFlowParseError('模板字段声明被截断', fieldCursor);
      fields.push({ type: buffer.readUInt16BE(fieldCursor), length: buffer.readUInt16BE(fieldCursor + 2) });
    }
    templates.push({ templateId, fields });
    cursor += 4 + fieldCount * 4;
  }
  return templates;
}

function parseOptionsTemplateFlowset(buffer, flowset) {
  const templates = [];
  let cursor = flowset.offset + 4;
  const end = flowset.offset + flowset.length;
  while (cursor < end) {
    if (end - cursor < 6) break; // 尾部对齐填充
    const templateId = buffer.readUInt16BE(cursor);
    const scopeLength = buffer.readUInt16BE(cursor + 2);
    const optionLength = buffer.readUInt16BE(cursor + 4);
    if (templateId < MIN_DATA_FLOWSET_ID) {
      throw new NetFlowParseError(`选项模板编号${templateId}不在数据编号范围`, cursor);
    }
    if (scopeLength % 4 !== 0 || optionLength % 4 !== 0 || scopeLength + optionLength === 0) {
      throw new NetFlowParseError('选项模板 scope/option 长度无效', cursor + 2);
    }
    const readFieldList = (start, byteLength) => {
      const list = [];
      for (let offset = 0; offset < byteLength; offset += 4) {
        const fieldCursor = start + offset;
        if (fieldCursor + 4 > end) throw new NetFlowParseError('选项模板字段声明被截断', fieldCursor);
        list.push({ type: buffer.readUInt16BE(fieldCursor), length: buffer.readUInt16BE(fieldCursor + 2) });
      }
      return list;
    };
    const scopeFields = readFieldList(cursor + 6, scopeLength);
    const optionFields = readFieldList(cursor + 6 + scopeLength, optionLength);
    templates.push({ templateId, scopeFields, optionFields, fields: [...scopeFields, ...optionFields] });
    cursor += 6 + scopeLength + optionLength;
  }
  return templates;
}

export function parseDatagram(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new NetFlowParseError('数据报必须是 Buffer');
  if (buffer.length < HEADER_LENGTH) throw new NetFlowParseError('数据报短于20字节v9头部');
  const version = buffer.readUInt16BE(0);
  if (version !== NETFLOW_VERSION) throw new NetFlowParseError(`不是NetFlow v9数据报（version=${version}）`, 0);
  const header = {
    version,
    count: buffer.readUInt16BE(2),
    sysUpTime: buffer.readUInt32BE(4),
    unixSeconds: buffer.readUInt32BE(8),
    sequence: buffer.readUInt32BE(12),
    sourceId: buffer.readUInt32BE(16),
  };
  const flowsets = [];
  let offset = HEADER_LENGTH;
  while (offset < buffer.length) {
    if (buffer.length - offset < 4) throw new NetFlowParseError('FlowSet 头部被截断', offset);
    const flowsetId = buffer.readUInt16BE(offset);
    const length = buffer.readUInt16BE(offset + 2);
    if (length < 4) throw new NetFlowParseError(`FlowSet ${flowsetId} 长度无效`, offset + 2);
    if (offset + length > buffer.length) throw new NetFlowParseError('FlowSet 超出数据报边界', offset);
    const base = { id: flowsetId, offset, length };
    if (flowsetId === TEMPLATE_FLOWSET_ID) {
      flowsets.push({ ...base, kind: 'template', templates: parseTemplateFlowset(buffer, base) });
    } else if (flowsetId === OPTIONS_TEMPLATE_FLOWSET_ID) {
      flowsets.push({ ...base, kind: 'optionsTemplate', templates: parseOptionsTemplateFlowset(buffer, base) });
    } else if (flowsetId >= MIN_DATA_FLOWSET_ID) {
      flowsets.push({ ...base, kind: 'data', dataOffset: offset + 4, dataBuffer: buffer });
    } else {
      throw new NetFlowParseError(`保留FlowSet编号${flowsetId}不在支持范围`, offset);
    }
    offset += length;
  }
  return { header, flowsets };
}

export function findField(fields, type) {
  return fields.find(field => field.type === type) ?? null;
}
