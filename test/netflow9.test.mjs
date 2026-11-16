import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseDatagram, decodeDataFlowset, NetFlowParseError } from '../src/netflow9.mjs';
import {
  v9Header, templateFlowset, optionsTemplateFlowset, dataFlowset, datagram,
  LAYOUT_A, LAYOUT_B,
} from './helpers.mjs';

const fixtures = JSON.parse(await readFile(new URL('../fixtures/packets.json', import.meta.url)));
const load = index => Buffer.from(fixtures[index].data, 'base64');

test('解析20字节v9头部与模板FlowSet，字段长度按模板声明', () => {
  const parsed = parseDatagram(load(0));
  assert.equal(parsed.header.version, 9);
  assert.equal(parsed.header.sourceId, 7);
  assert.equal(parsed.header.sequence, 1);
  assert.equal(parsed.flowsets[0].kind, 'template');
  assert.deepEqual(parsed.flowsets[0].templates[0].fields.map(f => f.type), [8, 12, 1, 10]);
  assert.equal(parsed.flowsets[0].templates[0].fields[2].length, 8);
});

test('选项模板按scope与option字节解析，尾部填充不产生假模板', () => {
  const parsed = parseDatagram(load(1));
  const options = parsed.flowsets.find(f => f.kind === 'optionsTemplate');
  assert.equal(options.templates[0].templateId, 300);
  assert.deepEqual(options.templates[0].scopeFields.map(f => f.type), [2]);
  assert.deepEqual(options.templates[0].optionFields.map(f => f.type), [34]);
  const data = parsed.flowsets.find(f => f.id === 300);
  assert.equal(data.kind, 'data');
});

test('同编号不同布局的两个模板各自按自身字段长度解释，端口与字节不会读反', () => {
  const templateA = parseDatagram(load(0)).flowsets[0].templates[0];
  const templateB = parseDatagram(load(2)).flowsets[0].templates[0];
  assert.equal(templateA.templateId, templateB.templateId);
  assert.notDeepEqual(templateA.fields, templateB.fields);

  const recordA = decodeDataFlowset(templateA, { ...parseDatagram(load(3)).flowsets[0] });
  const inBytesA = recordA.records[0].fields.find(f => f.type === 1);
  assert.equal(inBytesA.value, '9007199254741001');
  assert.equal(inBytesA.length, 8);
  assert.equal(recordA.records[0].fields.find(f => f.type === 8).value, '10.0.0.1');

  const recordB = decodeDataFlowset(templateB, parseDatagram(load(4)).flowsets[0]);
  const fieldsB = recordB.records[0].fields;
  assert.equal(fieldsB.find(f => f.type === 1).value, 100);
  assert.equal(fieldsB.find(f => f.type === 10).value, 8);
  // 若错用 A 布局，8 字节计数器会把后面 4 个字节吞掉，INPUT_SNMP 读到的就是计数器尾部（100），
  // 而不是真实接口号 8，正好暴露模板缓存按编号复用的问题。
  const wrong = decodeDataFlowset(templateA, parseDatagram(load(4)).flowsets[0]);
  assert.equal(wrong.records[0].fields.find(f => f.type === 10).value, 100);
});

test('大于安全整数的8字节计数保存为十进制字符串', () => {
  const parsed = parseDatagram(load(3));
  const template = { fields: LAYOUT_A };
  const { records } = decodeDataFlowset(template, parsed.flowsets[0]);
  const value = records[0].fields.find(f => f.type === 1).value;
  assert.equal(typeof value, 'string');
  assert.equal(value, '9007199254741001');
  assert.ok(BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER));
});

test('不认识的字段保留类型、长度与原始字节，不丢弃也不猜测语义', () => {
  const template = { fields: [...LAYOUT_A, { type: 999, length: 4 }] };
  const flowset = dataFlowset(256, template.fields, [{
    8: 0x0a000001, 12: 0x0a000002, 1: 9n, 10: 7, 999: 0x12345678,
  }]);
  const packet = datagram(v9Header({ count: 1, sysUpTime: 1, unixSeconds: 1, sequence: 1, sourceId: 7 }), flowset);
  const { records } = decodeDataFlowset(template, parseDatagram(packet).flowsets[0]);
  const unknown = records[0].fields.find(f => f.type === 999);
  assert.equal(unknown.name, null);
  assert.equal(unknown.length, 4);
  assert.equal(unknown.rawHex, '12345678');
});

test('FlowSet四字节对齐填充按模板边界跳过', () => {
  const fields = [{ type: 1, length: 4 }, { type: 10, length: 2 }]; // 单条6字节
  const template = { fields };
  const flowset = dataFlowset(256, fields, [{ 1: 42, 10: 7 }]); // 6字节记录+2字节填充
  assert.equal(flowset.length % 4, 0);
  const { records, paddingLength } = decodeDataFlowset(template, { dataOffset: 4, length: flowset.length }, flowset);
  assert.equal(records.length, 1);
  assert.equal(paddingLength, 2);
  assert.equal(records[0].fields[0].value, 42);
});

test('畸形数据报被明确拒绝而不是猜内容', () => {
  assert.throws(() => parseDatagram(Buffer.from([0, 9])), NetFlowParseError);
  const badVersion = Buffer.alloc(20);
  badVersion.writeUInt16BE(5, 0);
  assert.throws(() => parseDatagram(badVersion), /version=5/);
  const overrun = datagram(v9Header({ count: 1, sysUpTime: 1, unixSeconds: 1, sequence: 1, sourceId: 7 }));
  const broken = Buffer.concat([overrun, Buffer.from([0x01, 0x00, 0x00, 0x30])]); // 长度超出边界
  assert.throws(() => parseDatagram(broken), NetFlowParseError);
});

test('模板字段声明被截断时抛错', () => {
  const flowset = templateFlowset(256, LAYOUT_A).subarray(0, 10);
  flowset.writeUInt16BE(24, 2); // 声称长度超过实际
  const packet = datagram(v9Header({ count: 1, sysUpTime: 1, unixSeconds: 1, sequence: 1, sourceId: 7 }), flowset);
  assert.throws(() => parseDatagram(packet), NetFlowParseError);
});

test('保留FlowSet编号在支持范围外时报错', () => {
  const reserved = Buffer.alloc(8);
  reserved.writeUInt16BE(2, 0);
  reserved.writeUInt16BE(8, 2);
  const packet = datagram(v9Header({ count: 1, sysUpTime: 1, unixSeconds: 1, sequence: 1, sourceId: 7 }), reserved);
  assert.throws(() => parseDatagram(packet), /保留FlowSet/);
});

test('构造器生成的选项模板可被解析回scope与option', () => {
  const flowset = optionsTemplateFlowset(300, [{ type: 2, length: 4 }], [{ type: 34, length: 4 }]);
  const packet = datagram(v9Header({ count: 2, sysUpTime: 1, unixSeconds: 1, sequence: 1, sourceId: 7 }), flowset);
  const parsed = parseDatagram(packet);
  assert.equal(parsed.flowsets[0].templates[0].scopeFields[0].type, 2);
});

void LAYOUT_B;
