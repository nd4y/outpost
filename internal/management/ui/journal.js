const ID = /^[a-f0-9]{64}$/;
const FORMAT = "outpost-browser-journal-2";
const MAX = 3 * 1024 * 1024;
const oversized = (raw) => raw.length > MAX || new TextEncoder().encode(raw).byteLength > MAX;
export const terminal = (record) =>
  ["COMPLETE", "FAILED", "ABANDONED"].includes(record.receipt?.state);
const copy = (value) => structuredClone(value);
function recordsValid(records) {
  return (
    Array.isArray(records) &&
    records.length <= 16 &&
    new Set(records.map((r) => r?.operation)).size === records.length &&
    records.every(
      (r) =>
        r &&
        [r.operation, r.tenant, r.node, r.domain, r.fingerprint].every((v) => ID.test(v)) &&
        (r.accessDomains === undefined ||
          (Array.isArray(r.accessDomains) &&
            r.accessDomains.length <= 128 &&
            r.accessDomains.every((d) => ID.test(d)))) &&
        (!r.receipt || r.receipt.operationId === r.operation) &&
        (!r.resolution ||
          (ID.test(r.resolution.body?.operationId) &&
            r.resolution.body.operationId !== r.operation &&
            ID.test(r.resolution.body.targetRequestDigest) &&
            r.resolution.body.reason === "ABANDON_UNPUBLISHED" &&
            (!r.resolution.receipt ||
              r.resolution.receipt.operationId === r.resolution.body.operationId))) &&
        (r.type === "command"
          ? r.body &&
            r.body.operationId === r.operation &&
            r.body.tenant === r.tenant &&
            r.body.domain === r.domain &&
            typeof r.body.kind === "string"
          : r.type === "config" &&
            ID.test(r.digest) &&
            Number.isSafeInteger(r.expected) &&
            r.expected >= 0),
    )
  );
}

// Only this module writes the shared journal. Every read/modify/write is under
// the same origin/actor Web Lock. Network I/O never holds the lock.
export class OperationJournal {
  constructor(actor, changed) {
    if (!ID.test(actor)) throw new Error("STORAGE");
    this.key = `outpost-operations-2-${actor}`;
    this.legacy = `outpost-operations-1-${actor}`;
    this.changed = changed;
  }
  read() {
    try {
      const raw = localStorage.getItem(this.key);
      if (raw === null) return { format: FORMAT, revision: 0, records: [] };
      if (oversized(raw)) throw new Error();
      const value = JSON.parse(raw);
      if (
        value.format !== FORMAT ||
        !Number.isSafeInteger(value.revision) ||
        value.revision < 1 ||
        !recordsValid(value.records)
      )
        throw new Error();
      return value;
    } catch {
      throw new Error("STORAGE");
    }
  }
  snapshot() {
    const value = this.read();
    this.changed(copy(value.records));
    return copy(value);
  }
  async locked(fn) {
    if (!navigator.locks?.request) throw new Error("STORAGE");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      return await navigator.locks.request(this.key, { signal: controller.signal }, () => {
        const value = this.read();
        const result = fn(value);
        if (result.write) {
          if (!Number.isSafeInteger(value.revision + 1) || !recordsValid(value.records))
            throw new Error("STORAGE");
          value.revision++;
          const raw = JSON.stringify(value);
          try {
            if (oversized(raw)) throw new Error();
            localStorage.setItem(this.key, raw);
            if (localStorage.getItem(this.key) !== raw) throw new Error();
          } catch {
            throw new Error("STORAGE");
          }
        }
        this.changed(copy(value.records));
        return copy(result.value);
      });
    } catch (e) {
      if (e.name === "AbortError") throw new Error("BUSY");
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }
  async dispatch(action) {
    if (!navigator.locks?.request) throw new Error("STORAGE");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      return await navigator.locks.request(
        `${this.key}-dispatch`,
        { signal: controller.signal },
        action,
      );
    } catch (e) {
      if (e.name === "AbortError") throw new Error("BUSY");
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }
  async open() {
    // Migration preserves uncertain request IDs and bytes. It never clears a
    // previous journal until the merged new version has been read back.
    let raw;
    try {
      raw = sessionStorage.getItem(this.legacy);
    } catch {
      throw new Error("STORAGE");
    }
    if (raw !== null) {
      let records;
      try {
        if (oversized(raw)) throw new Error();
        records = JSON.parse(raw);
        if (!recordsValid(records)) throw new Error();
      } catch {
        throw new Error("STORAGE");
      }
      await this.locked((value) => {
        for (const record of records) {
          const old = value.records.find((r) => r.operation === record.operation);
          if (old) {
            for (const field of [
              "tenant",
              "node",
              "domain",
              "fingerprint",
              "type",
              "body",
              "digest",
              "expected",
            ])
              if (JSON.stringify(old[field]) !== JSON.stringify(record[field]))
                throw new Error("CONFLICT");
            if (!terminal(old) && terminal(record)) old.receipt = record.receipt;
          } else value.records.push({ ...record, saved: true });
        }
        if (value.records.length > 16) throw new Error("LIMIT");
        return { write: true };
      });
      try {
        sessionStorage.removeItem(this.legacy);
      } catch {
        /* Repeated merge is idempotent. */
      }
    }
    return this.snapshot();
  }
  async admit(candidate) {
    return this.locked((value) => {
      const exact = value.records.find((r) => r.operation === candidate.operation);
      if (exact) return { value: exact };
      // A removed completed record must not be resurrected by a stale tab.
      if (candidate.saved) throw new Error("CONFLICT");
      const latest = value.records.findLast(
        (r) => r.type === candidate.type && r.fingerprint === candidate.fingerprint,
      );
      if (latest && (latest.operation !== candidate.basedOn || !terminal(latest)))
        return { value: latest };
      if (candidate.journalRevision !== value.revision) throw new Error("CONFLICT");
      if (value.records.length >= 16) throw new Error("LIMIT");
      const { journalRevision, basedOn, freshDraft, ...record } = candidate;
      record.saved = true;
      value.records.push(record);
      return { write: true, value: record };
    });
  }
  async receipt(operation, receipt) {
    if (receipt.operationId !== operation) throw new Error("INVALID");
    return this.locked((value) => {
      const old = value.records.find((r) => r.operation === operation);
      if (!old) return { value: receipt }; // A different tab removed a terminal record.
      if (terminal(old)) return { value: old.receipt };
      old.receipt = receipt;
      return { write: true, value: receipt };
    });
  }
  async authorize(operation, accessDomains) {
    return this.locked((value) => {
      const old = value.records.find((r) => r.operation === operation);
      if (!old) throw new Error("CONFLICT");
      if (old.accessDomains) return {};
      old.accessDomains = accessDomains;
      return { write: true };
    });
  }
  async prepareResolution(operation, body) {
    return this.locked((value) => {
      const old = value.records.find((r) => r.operation === operation);
      if (!old) throw new Error("CONFLICT");
      if (old.resolution) {
        if (old.resolution.body.targetRequestDigest !== body.targetRequestDigest)
          throw new Error("CONFLICT");
        return { value: old.resolution.body };
      }
      if (terminal(old)) throw new Error("CONFLICT");
      if (
        value.records.some(
          (r) =>
            r.operation === body.operationId || r.resolution?.body.operationId === body.operationId,
        )
      )
        throw new Error("CONFLICT");
      old.resolution = { body };
      return { write: true, value: body };
    });
  }
  async resolved(operation, receipt) {
    return this.locked((value) => {
      const old = value.records.find((r) => r.operation === operation);
      if (!old) return {};
      if (old.resolution?.body.operationId !== receipt.operationId || receipt.state !== "COMPLETE")
        throw new Error("INVALID");
      if (old.resolution.receipt) return {};
      old.resolution.receipt = receipt;
      return { write: true };
    });
  }
  async remove(operation) {
    return this.locked((value) => {
      const old = value.records.find((r) => r.operation === operation);
      if (!old) return {};
      if (!terminal(old)) throw new Error("CONFLICT");
      value.records = value.records.filter((r) => r.operation !== operation);
      return { write: true };
    });
  }
}
