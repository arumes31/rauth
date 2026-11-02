import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
const coreSource = await readFile(
  new URL("../static/js/management/stats-core.js", import.meta.url),
  "utf8",
);
const core = await import(
  "data:text/javascript;base64," + Buffer.from(coreSource).toString("base64")
);
class Element {
  constructor(tag = "div") {
    this.tagName = tag;
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.listeners = new Map();
    this.value = "";
    this.hidden = false;
    this.text = "";
  }
  set textContent(value) {
    this.text = String(value);
    this.children = [];
  }
  get textContent() {
    return this.text + this.children.map((c) => c.textContent).join("");
  }
  set innerHTML(_) {
    throw new Error("Untrusted content must use textContent");
  }
  prepend(...children) {
    this.children.unshift(...children);
  }
  append(...children) {
    this.children.push(...children);
  }
  replaceChildren(...children) {
    this.children = [];
    this.text = "";
    this.append(...children);
  }
  setAttribute(name, value) {
    this[name] = String(value);
  }
  addEventListener(name, fn) {
    this.listeners.set(name, fn);
  }
  fire(name) {
    return this.listeners.get(name)?.({ preventDefault() {} });
  }
  get options() {
    return this.children;
  }
  querySelector(tag) {
    return this.children.find((c) => c.tagName === tag) || null;
  }
}
const nodeID = "11111111-1111-4111-8111-111111111111";
const now = "2026-11-02T02:00:00Z",
  start = "2026-11-02T01:00:00Z";
const payload = {
  generated_at: now,
  start,
  end: now,
  bucket_seconds: 60,
  total: 9,
  actions: [
    { key: "blocked", count: 7 },
    { key: "bypass", count: 2 },
  ],
  timeline: [{ time: now, action: "blocked", count: 7 }],
  latency: { p50_ms: 1, p95_ms: 10, p99_ms: 30, samples: 9, unknown: 0 },
  latency_timeline: [{ time: now, p50_ms: 1, p95_ms: 10, p99_ms: 30 }],
  countries: [{ key: "AT", count: 9 }],
  top: {
    urls: [{ key: "https://example.test/<img onerror=alert(1)>", count: 9 }],
  },
  nodes: [
    {
      node_id: nodeID,
      node_name: "<worker>",
      time: now,
      snapshot: { started_at: start, go_version: "test", points: [] },
      rates: {},
    },
  ],
  retained_since: start,
  expired: 0,
  loss_markers: 0,
  coverage: "retained history",
};
async function fixture({ mapStatus = 200 } = {}) {
  const template = await readFile(
    new URL("../templates/stats.html", import.meta.url),
    "utf8",
  );
  const ids = [...template.matchAll(/id="([^"]+)"/g)].map((m) => m[1]);
  const elements = new Map(ids.map((id) => [id, new Element()]));
  elements.set("pageTitle", new Element());
  const form = elements.get("statsFilters");
  form.elements = {
    range: new Element(),
    node: elements.get("statsNode"),
    country: elements.get("statsCountry"),
    action: new Element(),
  };
  form.elements.range.value = "1h";
  form.reset = () => {
    for (const field of Object.values(form.elements)) field.value = "";
    form.elements.range.value = "1h";
  };
  class EventSource {
    static all = [];
    constructor(url) {
      this.url = url;
      this.handlers = new Map();
      EventSource.all.push(this);
    }
    addEventListener(name, fn) {
      this.handlers.set(name, fn);
    }
    close() {
      this.closed = true;
    }
    emit(name, data) {
      this.handlers.get(name)?.({ data: JSON.stringify(data) });
    }
  }
  class FormData {
    constructor(form) {
      this.form = form;
    }
    *[Symbol.iterator]() {
      for (const [key, el] of Object.entries(this.form.elements))
        yield [key, el.value];
    }
  }
  const fetches = [];
  const document = {
    getElementById: (id) => elements.get(id) || null,
    createElement: (tag) => new Element(tag),
    createElementNS: (_, tag) => new Element(tag),
    createTextNode: (value) => {
      const node = new Element("text");
      node.textContent = value;
      return node;
    },
  };
  const fetch = async (url) => {
    fetches.push(url);
    return {
      ok: !url.includes("/static/") || mapStatus === 200,
      json: async () =>
        url.includes("/static/")
          ? []
          : url.includes("/history")
            ? {
                events: [
                  {
                    time: now,
                    url: "<script>secret</script>",
                    source: "203.0.113.5",
                    country: "AT",
                    action: "blocked",
                    node_name: "<worker>",
                    node_id: nodeID,
                    processing_us: 1000,
                  },
                ],
                before: 0,
              }
            : url.includes("/diagnostics")
              ? { time: now, complete: true, parts: [] }
              : {},
    };
  };
  const context = vm.createContext({
    document,
    window: { addEventListener() {} },
    EventSource,
    FormData,
    URLSearchParams,
    AbortController,
    fetch,
    initWidgets() {},
    setInterval: () => 1,
    clearInterval() {},
    console,
  });
  const source = await readFile(
    new URL("../static/js/stats.js", import.meta.url),
    "utf8",
  );
  vm.runInContext(
    coreSource.replace(/export /g, "") +
      "\n" +
      source.replace(/^import[\s\S]*?from\s+['"][^'"]+['"];?/gm, ""),
    context,
  );
  await new Promise((resolve) => setImmediate(resolve));
  return { elements, EventSource, stream: EventSource.all[0], fetches };
}
test("Stats numeric formatters distinguish absent coverage from zero", () => {
  assert.equal(core.formatNumber(null), "—");
  assert.equal(core.formatNumber(0), "0");
  assert.equal(core.milliseconds(NaN), "—");
  assert.equal(core.chartPosition(now, start, now, 500), 500);
  assert.equal(core.chartPosition("invalid", start, now, 500), null);
  assert.deepEqual(core.summary(payload), {
    Total: 9,
    Allowed: 2,
    Blocked: 7,
    Login: 0,
    Errors: 0,
  });
});
test("Stats renders node and original client separately as text and keeps local assets", async () => {
  const f = await fixture();
  f.stream.emit("stats", payload);
  assert.equal(f.elements.get("statTotal").textContent, "9");
  assert.match(f.elements.get("statsNodes").textContent, /<worker>/);
  assert.match(f.elements.get("statsHistory").textContent, /203.0.113.5/);
  assert.match(
    f.elements.get("statsHistory").textContent,
    /<script>secret<\/script>/,
  );
  assert.match(f.elements.get("statsTopurls").textContent, /<img/);
  assert.ok(f.fetches.every((url) => url.startsWith("/")));
  assert.match(
    f.elements.get("statsCoverage").textContent,
    /not zero|histogram estimates/,
  );
});
test("Stats pause/filter invalidates old streams and preserves new query scope", async () => {
  const f = await fixture();
  f.stream.emit("stats", payload);
  await f.elements.get("statsPause").fire("click");
  assert.equal(f.stream.closed, true);
  f.stream.emit("stats", { ...payload, total: 999 });
  assert.equal(f.elements.get("statTotal").textContent, "9");
  f.elements.get("statsNode").value = nodeID;
  await f.elements.get("statsFilters").fire("change");
  assert.equal(
    f.EventSource.all.length,
    1,
    "paused filter must not create a stream",
  );
  await f.elements.get("statsPause").fire("click");
  assert.match(f.EventSource.all.at(-1).url, new RegExp("node=" + nodeID));
  f.EventSource.all.at(-1).emit("unavailable", {});
  assert.match(f.elements.get("statsConnection").textContent, /stale/);
  f.EventSource.all.at(-1).emit("session-ended", {});
  assert.equal(f.EventSource.all.at(-1).closed, true);
});

test("unavailable map preserves a visible notice after traffic tables render", async () => {
  const f = await fixture({ mapStatus: 404 });
  f.stream.emit("stats", payload);
  assert.match(f.elements.get("statsMapStatus").textContent, /Map unavailable/);
  assert.match(f.elements.get("statsCountries").textContent, /AT/);
});
