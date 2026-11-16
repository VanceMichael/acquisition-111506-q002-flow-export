// 有状态的 NetFlow v9 收件引擎。
// 身份与有效域：出口地址 + Source ID 标识导出源，运行世代隔离模板与采样声明；
// 模板编号只在“出口 + Source ID + 世代”范围内有效，绝不跨世代复用。
// 所有状态变化都写成事件交给存储，重放事件即可重建全部内存状态。

import { createHash } from 'node:crypto';
import {
  parseDatagram,
  decodeDataFlowset,
  findField,
  SEQUENCE_WRAP,
  UPTIME_WRAP,
  FIELD_DICTIONARY,
} from './netflow9.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const digestOf = text => createHash('sha256').update(text).digest('hex');
const EVICTION_LOG_LIMIT = 1000;

export const DEFAULT_LIMITS = {
  pendingTtlMs: 5 * 60 * 1000,
  maxPendingPerExporter: 1000,
  sweepIntervalMs: 30 * 1000,
};

function mod32(value) {
  return ((value % SEQUENCE_WRAP) + SEQUENCE_WRAP) % SEQUENCE_WRAP;
}

function multiplyCounter(value, interval) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') {
    const product = BigInt(value) * BigInt(interval);
    return product <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(product) : product.toString();
  }
  const product = value * interval;
  return Number.isSafeInteger(product) ? product : (BigInt(value) * BigInt(interval)).toString();
}

export function createCollector(store, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const clock = options.clock ?? (() => new Date());
  const events = [];

  // 每个导出源（出口地址 + Source ID）独立一份世代与序号状态。
  const exporters = new Map();
  const flows = [];
  const datagrams = [];
  const evictions = [];
  const templateStore = new Map(); // key -> 模板定义
  const pending = []; // 等待模板的 Data FlowSet，有界
  const samplingStore = new Map(); // exporterKey#generation#scopeInterface -> 声明
  let sweepTimer = null;
  // UDP 收包是并发回调；同一收集器内必须串行处理，否则出口序号状态会发生竞态。
  let ingestQueue = Promise.resolve();

  const templateKey = (exporterKey, generation, templateId) =>
    `${exporterKey}#g${generation}#t${templateId}`;

  function publish(event) {
    const stored = { eventId: `ev_${events.length + 1}`, at: clock().toISOString(), ...event };
    events.push(stored);
    if (store) awaitStore(stored);
    return stored;
  }

  let pendingWrites = Promise.resolve();
  function awaitStore(event) {
    pendingWrites = pendingWrites.then(() => store.appendNetflow(event)).catch(error => {
      // 落盘失败不应让 UDP 接收崩溃，但要在出口状态上留下可查询痕迹。
      event.persistenceError = error.message;
    });
  }

  function getExporter(exporterKey) {
    let exporter = exporters.get(exporterKey);
    if (!exporter) {
      exporter = {
        exporterKey,
        generations: [],
        lastSequence: null,
        lastSysUpTime: null,
        lastUnixSeconds: null,
        lastDatagramSha: null,
        datagramCount: 0,
        duplicateCount: 0,
        gapCount: 0,
        restartCount: 0,
        anomalies: [],
        pendingCount: 0,
      };
      exporters.set(exporterKey, exporter);
    }
    return exporter;
  }

  function startGeneration(exporter, basis, certainty, header, datagramId, at) {
    const generation = exporter.generations.length;
    const detail = {
      exporterKey: exporter.exporterKey,
      generation,
      basis,
      certainty,
      startedAt: at,
      firstDatagramId: datagramId,
      firstSequence: header.sequence,
      firstSysUpTime: header.sysUpTime,
      unixSeconds: header.unixSeconds,
      sourceId: header.sourceId,
    };
    exporter.generations.push(detail);
    if (generation > 0) exporter.restartCount += 1;
    publish({ type: 'generation-started', ...detail });
    return generation;
  }

  // 序号只按导出包递增；缺口是“数据报序号缺口”，不是业务流丢失条数。
  function observeSequence(exporter, header, datagramSha, datagramId, at) {
    const observation = {
      duplicate: false,
      duplicateOf: null,
      gap: null,
      restart: null,
      anomalies: [],
      generation: exporter.generations.length ? exporter.generations.length - 1 : 0,
    };
    if (exporter.lastSequence === null) return observation;

    observation.generation = exporter.generations.length - 1;
    const delta = mod32(header.sequence - exporter.lastSequence);
    const sequenceWentBack = header.sequence < exporter.lastSequence;
    const uptimeWentBack = header.sysUpTime < exporter.lastSysUpTime;
    const wallDelta = header.unixSeconds - exporter.lastUnixSeconds;
    // 32 位毫秒回绕约 49.7 天；用墙钟间隔佐证，不能只凭 sysUptime 数值下降就切换世代。
    const wrapExplained = uptimeWentBack && wallDelta >= UPTIME_WRAP / 1000 - 60;

    if (delta === 0) {
      if (datagramSha === exporter.lastDatagramSha) {
        observation.duplicate = true;
        observation.duplicateOf = exporter.lastDatagramId;
      } else {
        observation.anomalies.push('sequence-number-reused');
      }
      return observation;
    }

    if (sequenceWentBack) {
      // 序号倒退：可能是 32 位回绕，也可能是设备重启。结合 sysUptime 与 unixSecs 判定。
      if (uptimeWentBack && !wrapExplained) {
        const certainty = header.unixSeconds === 0 ? 'uncertain' : 'confirmed';
        observation.restart = {
          basis: 'sequence-and-uptime-reset',
          certainty,
          previousSequence: exporter.lastSequence,
          previousSysUpTime: exporter.lastSysUpTime,
        };
      } else {
        observation.anomalies.push(wrapExplained ? 'uptime-32bit-wrap' : 'sequence-32bit-wrap');
      }
      return observation;
    }

    if (wrapExplained) {
      // 序号仍在前进，sysUptime 下降但墙钟跨度足够大：是回绕不是重启，世代保持不变。
      observation.anomalies.push('uptime-32bit-wrap');
      return observation;
    }

    if (delta > 1) {
      observation.gap = {
        expectedNext: mod32(exporter.lastSequence + 1),
        received: header.sequence,
        missingDatagramSequences: Array.from({ length: Math.min(delta - 1, 100) }, (_, index) =>
          mod32(exporter.lastSequence + 1 + index)),
        missingDatagramCount: delta - 1,
        note: '缺口是数据报序号，不能据此推算丢失的业务流条数',
      };
    }
    if (uptimeWentBack) {
      // 序号仍在前进，只有 sysUptime 下降且墙钟不足以解释回绕：记录异常但不切换世代。
      observation.anomalies.push('sysuptime-decreased-without-restart');
    }
    return observation;
  }

  function registerTemplates(exporterKey, generation, flowset, datagramId, at) {
    for (const template of flowset.templates) {
      const key = templateKey(exporterKey, generation, template.templateId);
      const previous = templateStore.get(key);
      const kind = flowset.kind === 'optionsTemplate' ? 'optionsTemplate' : 'template';
      const revision = previous ? previous.revision + 1 : 0;
      const definition = {
        exporterKey,
        generation,
        templateId: template.templateId,
        kind,
        fields: template.fields,
        scopeFields: template.scopeFields ?? null,
        revision,
        datagramId,
        definedAt: at,
      };
      templateStore.set(key, definition);
      publish({
        type: 'template-defined',
        exporterKey,
        generation,
        templateId: template.templateId,
        kind,
        revision,
        redefined: Boolean(previous),
        fields: template.fields,
        scopeFields: template.scopeFields ?? null,
        datagramId,
        at,
      });
    }
  }

  function lookupSampling(exporterKey, generation, inputSnmp) {
    if (inputSnmp === null || inputSnmp === undefined) return { status: 'unknown', reason: '记录缺少 INPUT_SNMP，无法匹配接口作用域' };
    const declaration = samplingStore.get(`${exporterKey}#g${generation}#if${inputSnmp}`);
    if (!declaration) return { status: 'unknown', reason: '当前世代没有覆盖该接口的采样声明' };
    return {
      status: 'configured',
      interval: declaration.interval,
      scopeInterface: declaration.scopeInterface,
      declarationDatagramId: declaration.datagramId,
    };
  }

  function buildFlow({ exporterKey, generation, template, flowsetId, decoded, recordIndex, datagramId, datagramSha, header, templateBasis, pendingId = null }) {
    const fields = decoded.fields;
    const inBytesField = findField(fields, 1);
    const sourceField = findField(fields, 8);
    const destinationField = findField(fields, 12);
    const inputField = findField(fields, 10);
    const inputSnmp = inputField ? inputField.value : null;
    const sampling = lookupSampling(exporterKey, generation, inputSnmp);
    const measured = { inBytes: inBytesField ? inBytesField.value : null };
    const estimated = sampling.status === 'configured'
      ? { inBytes: multiplyCounter(measured.inBytes, sampling.interval), basis: `IN_BYTES × SAMPLING_INTERVAL(${sampling.interval})`, kind: 'extrapolated' }
      : { inBytes: null, basis: null, kind: 'unavailable' };
    const flowId = digestOf([
      exporterKey, generation, datagramSha, flowsetId, recordIndex, template.revision,
    ].join('|'));
    return {
      flowId,
      exporterKey,
      generation,
      sourceId: header.sourceId,
      templateId: flowsetId,
      templateRevision: template.revision,
      templateBasis,
      pendingId,
      datagramId,
      datagramSha256: datagramSha,
      sequence: header.sequence,
      recordIndex,
      sourceIpv4: sourceField ? sourceField.value : null,
      destinationIpv4: destinationField ? destinationField.value : null,
      inputSnmp,
      fields,
      unknownFields: fields.filter(field => !FIELD_DICTIONARY[field.type]).map(field => ({
        type: field.type, length: field.length, rawHex: field.rawHex,
      })),
      sampling,
      measured,
      estimated,
    };
  }

  function resolvePending(exporterKey, generation, templateId, at) {
    const matched = pending.filter(entry =>
      entry.exporterKey === exporterKey && entry.generation === generation && entry.templateId === templateId);
    for (const entry of matched) {
      const template = templateStore.get(templateKey(exporterKey, generation, templateId));
      const datagram = datagrams.find(item => item.datagramId === entry.datagramId);
      try {
        const flowset = {
          offset: entry.flowset.offset,
          length: entry.flowset.length,
          dataOffset: entry.flowset.dataOffset,
          dataBuffer: entry.raw,
        };
        const { records } = decodeDataFlowset(template, flowset, entry.raw);
        const flowIds = [];
        for (const [recordIndex, decoded] of records.entries()) {
          const flow = buildFlow({
            exporterKey, generation, template, flowsetId: templateId, decoded, recordIndex,
            datagramId: entry.datagramId, datagramSha: datagram.sha256, header: entry.header,
            templateBasis: template.revision > 0 ? 'late-template-redefined' : 'late-template',
            pendingId: entry.pendingId,
          });
          flows.push(flow);
          flowIds.push(flow.flowId);
          publish({ type: 'flow-record', flow });
        }
        entry.status = 'resolved';
        entry.resolvedAt = at;
        publish({ type: 'pending-resolved', pendingId: entry.pendingId, flowIds, at, templateRevision: template.revision });
      } catch (error) {
        entry.status = 'decode-error';
        entry.error = error.message;
        publish({ type: 'pending-evicted', pendingId: entry.pendingId, reason: 'decode-error', detail: error.message, at, datagramId: entry.datagramId, templateId, sequence: entry.header.sequence });
      }
    }
    for (const entry of matched) {
      const index = pending.indexOf(entry);
      if (index >= 0 && entry.status !== 'waiting') pending.splice(index, 1);
    }
    const exporter = exporters.get(exporterKey);
    if (exporter) exporter.pendingCount = pending.filter(item => item.exporterKey === exporterKey).length;
  }

  function evictPending(entry, reason, at, detail = null) {
    entry.status = reason;
    evictions.push({
      pendingId: entry.pendingId, reason, detail, at,
      exporterKey: entry.exporterKey, generation: entry.generation,
      templateId: entry.templateId, sequence: entry.header.sequence,
      datagramId: entry.datagramId,
    });
    if (evictions.length > EVICTION_LOG_LIMIT) evictions.shift();
    publish({ type: 'pending-evicted', pendingId: entry.pendingId, reason, detail, at, datagramId: entry.datagramId, templateId: entry.templateId, sequence: entry.header.sequence, exporterKey: entry.exporterKey, generation: entry.generation });
  }

  function sweep(at = clock().toISOString()) {
    // 先按 TTL 到期，再按每出口容量裁剪，保证等待区不会无限占用内存。
    for (const entry of [...pending]) {
      if (entry.status === 'waiting' && Date.parse(at) - Date.parse(entry.receivedAt) > limits.pendingTtlMs) {
        evictPending(entry, 'expired-ttl', at);
      }
    }
    for (let index = pending.length - 1; index >= 0; index--) {
      if (pending[index].status !== 'waiting') pending.splice(index, 1);
    }
    const byExporter = new Map();
    for (const entry of pending) {
      const list = byExporter.get(entry.exporterKey) ?? [];
      list.push(entry);
      byExporter.set(entry.exporterKey, list);
    }
    for (const list of byExporter.values()) {
      const overflow = list.length - limits.maxPendingPerExporter;
      for (let index = 0; index < overflow; index += 1) evictPending(list[index], 'evicted-capacity', at);
    }
    for (let index = pending.length - 1; index >= 0; index--) {
      if (pending[index].status !== 'waiting') pending.splice(index, 1);
    }
    for (const [key, exporter] of exporters) {
      exporter.pendingCount = pending.filter(item => item.exporterKey === key).length;
    }
  }

  function handleOptionsData(exporterKey, generation, template, flowset, raw, datagramId, header, at) {
    const { records } = decodeDataFlowset(template, flowset, raw);
    for (const decoded of records) {
      const scopeField = decoded.fields.find(field => field.type === (template.scopeFields?.[0]?.type ?? 2)) ?? findField(decoded.fields, 2);
      const intervalField = findField(decoded.fields, 34);
      if (!scopeField || !intervalField) continue; // 样例范围外的选项数据不猜测
      const declaration = {
        exporterKey,
        generation,
        templateId: template.templateId,
        scopeInterface: scopeField.value,
        interval: intervalField.value,
        datagramId,
        sequence: header.sequence,
        at,
      };
      samplingStore.set(`${exporterKey}#g${generation}#if${scopeField.value}`, declaration);
      publish({ type: 'sampling-declared', ...declaration });
    }
  }

  async function ingestOne(raw, remote) {
    const at = clock().toISOString();
    const sha = sha256(raw);
    const datagramId = `dg_${digestOf(`${sha}|${at}|${remote.address}`).slice(0, 16)}`;
    let parsed;
    try {
      parsed = parseDatagram(raw);
    } catch (error) {
      const entry = {
        datagramId, sha256: sha, at, size: raw.length,
        remote: { address: remote.address, sourcePort: remote.sourcePort ?? null },
        parseStatus: 'error', parseError: error.message,
      };
      datagrams.push(entry);
      if (store) await store.saveBlob(raw);
      publish({ type: 'datagram-received', ...entry });
      return { datagramId, accepted: false, parseError: error.message };
    }

    const { header, flowsets } = parsed;
    const exporterKey = `${remote.address}#src${header.sourceId}`;
    const exporter = getExporter(exporterKey);
    const observation = observeSequence(exporter, header, sha, datagramId, at);

    let generation = observation.generation;
    if (exporter.lastSequence === null) {
      generation = startGeneration(exporter, 'first-datagram', 'confirmed', header, datagramId, at);
    } else if (observation.restart) {
      // restartCount 由 generation-started 的归并逻辑统一维护，实时与重放走同一计数口径。
      generation = startGeneration(exporter, observation.restart.basis, observation.restart.certainty, header, datagramId, at);
    }

    const datagramEntry = {
      datagramId,
      exporterKey,
      sha256: sha,
      at,
      size: raw.length,
      remote: { address: remote.address, sourcePort: remote.sourcePort ?? null },
      header,
      parseStatus: 'ok',
      generation,
      sequence: header.sequence,
      duplicate: observation.duplicate,
      duplicateOf: observation.duplicateOf,
      gap: observation.gap,
      restart: observation.restart,
      anomalies: observation.anomalies,
      flowsetCount: flowsets.length,
    };
    datagrams.push(datagramEntry);
    if (store) await store.saveBlob(raw);
    publish({ type: 'datagram-received', ...datagramEntry });

    if (observation.gap) {
      exporter.gapCount += 1;
      publish({ type: 'sequence-gap', exporterKey, datagramId, at, ...observation.gap });
    }
    for (const anomaly of observation.anomalies) {
      exporter.anomalies.push({ anomaly, datagramId, at, sequence: header.sequence });
      publish({ type: 'sequence-anomaly', exporterKey, anomaly, datagramId, at, sequence: header.sequence });
    }
    if (observation.restart) {
      publish({ type: 'restart-detected', exporterKey, datagramId, at, generation, ...observation.restart });
    }
    if (observation.duplicate) {
      exporter.duplicateCount += 1;
      publish({ type: 'sequence-duplicate', exporterKey, datagramId, duplicateOf: observation.duplicateOf, at, sequence: header.sequence });
      // 完全重复的数据报不重复解释 FlowSet，避免业务流重复计数。
      exporter.lastDatagramSha = sha;
      exporter.lastDatagramId = datagramId;
      exporter.datagramCount += 1;
      sweep(at);
      await pendingWrites;
      return { datagramId, accepted: true, duplicate: true, generation, flows: 0 };
    }

    let flowCount = 0;
    for (const flowset of flowsets) {
      if (flowset.kind === 'template' || flowset.kind === 'optionsTemplate') {
        registerTemplates(exporterKey, generation, flowset, datagramId, at);
        for (const template of flowset.templates) resolvePending(exporterKey, generation, template.templateId, at);
        continue;
      }
      const template = templateStore.get(templateKey(exporterKey, generation, flowset.id));
      if (!template) {
        // 没有适用模板：原始字节保留，进入有界等待区，绝不猜字段。
        const pendingId = `pq_${digestOf(`${datagramId}|${flowset.offset}`).slice(0, 16)}`;
        const entry = {
          pendingId,
          status: 'waiting',
          exporterKey,
          generation,
          templateId: flowset.id,
          datagramId,
          header,
          raw,
          flowset: { offset: flowset.offset, length: flowset.length, dataOffset: flowset.dataOffset },
          receivedAt: at,
        };
        pending.push(entry);
        exporter.pendingCount += 1;
        publish({
          type: 'pending-stored', pendingId, exporterKey, generation, templateId: flowset.id,
          datagramId, sequence: header.sequence, receivedAt: at,
        });
        continue;
      }
      if (template.kind === 'optionsTemplate') {
        handleOptionsData(exporterKey, generation, template, flowset, raw, datagramId, header, at);
        continue;
      }
      const { records } = decodeDataFlowset(template, flowset, raw);
      for (const [recordIndex, decoded] of records.entries()) {
        const flow = buildFlow({
          exporterKey, generation, template, flowsetId: flowset.id, decoded, recordIndex,
          datagramId, datagramSha: sha, header, templateBasis: 'active-template',
        });
        flows.push(flow);
        flowCount += 1;
        publish({ type: 'flow-record', flow });
      }
    }

    exporter.lastSequence = header.sequence;
    exporter.lastSysUpTime = header.sysUpTime;
    exporter.lastUnixSeconds = header.unixSeconds;
    exporter.lastDatagramSha = sha;
    exporter.lastDatagramId = datagramId;
    exporter.datagramCount += 1;
    sweep(at);
    await pendingWrites;
    return { datagramId, accepted: true, duplicate: false, generation, flows: flowCount };
  }

  // ---- 重放：按事件顺序重建全部派生状态 ----
  function restore(event) {
    events.push(event);
    switch (event.type) {
      case 'datagram-received': {
        datagrams.push(event);
        if (event.exporterKey) {
          const exporter = getExporter(event.exporterKey);
          exporter.datagramCount += 1;
          if (event.duplicate) exporter.duplicateCount += 1;
          if (event.gap) exporter.gapCount += 1;
          for (const anomaly of event.anomalies ?? []) exporter.anomalies.push({ anomaly, datagramId: event.datagramId, at: event.at, sequence: event.sequence });
          exporter.lastSequence = event.header?.sequence ?? exporter.lastSequence;
          exporter.lastSysUpTime = event.header?.sysUpTime ?? exporter.lastSysUpTime;
          exporter.lastUnixSeconds = event.header?.unixSeconds ?? exporter.lastUnixSeconds;
          exporter.lastDatagramSha = event.sha256;
          exporter.lastDatagramId = event.datagramId;
        }
        break;
      }
      case 'generation-started': {
        const exporter = getExporter(event.exporterKey);
        if (!exporter.generations.some(generation => generation.generation === event.generation)) {
          exporter.generations.push({
            exporterKey: event.exporterKey, generation: event.generation, basis: event.basis,
            certainty: event.certainty, startedAt: event.startedAt, firstDatagramId: event.firstDatagramId,
            firstSequence: event.firstSequence, firstSysUpTime: event.firstSysUpTime,
            unixSeconds: event.unixSeconds, sourceId: event.sourceId,
          });
          if (event.generation > 0) exporter.restartCount += 1; // 重放路径的世代归并计数
        }
        break;
      }
      case 'template-defined': {
        templateStore.set(templateKey(event.exporterKey, event.generation, event.templateId), {
          exporterKey: event.exporterKey, generation: event.generation, templateId: event.templateId,
          kind: event.kind, fields: event.fields, scopeFields: event.scopeFields,
          revision: event.revision, datagramId: event.datagramId, definedAt: event.at,
        });
        break;
      }
      case 'sampling-declared': {
        samplingStore.set(`${event.exporterKey}#g${event.generation}#if${event.scopeInterface}`, {
          exporterKey: event.exporterKey, generation: event.generation, templateId: event.templateId,
          scopeInterface: event.scopeInterface, interval: event.interval,
          datagramId: event.datagramId, sequence: event.sequence, at: event.at,
        });
        break;
      }
      case 'flow-record':
        flows.push(event.flow);
        break;
      case 'pending-stored': {
        const datagram = datagrams.find(item => item.datagramId === event.datagramId);
        pending.push({
          pendingId: event.pendingId, status: 'waiting', exporterKey: event.exporterKey,
          generation: event.generation, templateId: event.templateId, datagramId: event.datagramId,
          header: datagram?.header ?? { sequence: event.sequence }, raw: null,
          flowset: null, receivedAt: event.receivedAt,
        });
        const exporter = getExporter(event.exporterKey);
        exporter.pendingCount += 1;
        break;
      }
      case 'pending-resolved':
      case 'pending-evicted': {
        const index = pending.findIndex(item => item.pendingId === event.pendingId);
        if (index >= 0) {
          const entry = pending.splice(index, 1)[0];
          const exporter = exporters.get(entry.exporterKey);
          if (exporter) exporter.pendingCount = Math.max(0, exporter.pendingCount - 1);
          if (event.type === 'pending-evicted') {
            evictions.push({
              pendingId: event.pendingId, reason: event.reason, detail: event.detail ?? null, at: event.at,
              exporterKey: event.exporterKey, generation: event.generation,
              templateId: event.templateId, sequence: event.sequence, datagramId: event.datagramId,
            });
          }
        }
        break;
      }
      default:
        break;
    }
  }

  async function replay(storedEvents) {
    for (const event of storedEvents) restore(event);
    sweep(); // 重放后按当前时间重新判定 TTL，等待区依然有界
  }

  function startSweeper() {
    if (sweepTimer || limits.sweepIntervalMs <= 0) return;
    sweepTimer = setInterval(() => sweep(), limits.sweepIntervalMs);
    sweepTimer.unref();
  }

  // 串行化所有实时收包，保证“出口 + Source ID”的序号与世代观察按到达次序发生。
  function ingest(raw, remote) {
    const result = ingestQueue.then(() => ingestOne(raw, remote));
    ingestQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  function snapshotExporters() {
    return [...exporters.values()].map(exporter => ({
      exporterKey: exporter.exporterKey,
      address: exporter.exporterKey.split('#src')[0],
      sourceId: exporter.generations[0]?.sourceId ?? null,
      datagramCount: exporter.datagramCount,
      duplicateCount: exporter.duplicateCount,
      gapCount: exporter.gapCount,
      restartCount: exporter.restartCount,
      pendingCount: exporter.pendingCount,
      lastSequence: exporter.lastSequence,
      lastSysUpTime: exporter.lastSysUpTime,
      generations: exporter.generations.map(generation => ({
        generation: generation.generation,
        basis: generation.basis,
        certainty: generation.certainty,
        startedAt: generation.startedAt,
        firstSequence: generation.firstSequence,
      })),
      anomalies: exporter.anomalies.slice(-50),
    }));
  }

  return {
    ingest,
    replay,
    startSweeper,
    async flush() { await pendingWrites; },
    limits,
    snapshot() {
      return {
        exporters: snapshotExporters(),
        flows: structuredClone(flows),
        datagrams: structuredClone(datagrams),
        templates: [...templateStore.values()].map(template => structuredClone(template)),
        pending: pending.map(({ raw, flowset, ...entry }) => structuredClone(entry)),
        evictions: structuredClone(evictions),
        samplingDeclarations: [...samplingStore.values()].map(item => structuredClone(item)),
      };
    },
  };
}
