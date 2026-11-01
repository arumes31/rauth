import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const code = await readFile(new URL('../static/js/management/policy-sync.js', import.meta.url), 'utf8');
const { initPolicySync } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
class Element {
 constructor() { this.children = []; this.text = ''; this.listeners = {}; }
 set textContent(value) { this.text = String(value); this.children = []; }
 get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
 set innerHTML(_) { throw new Error('Untrusted policy status must never enter innerHTML'); }
 append(...items) { this.children.push(...items); }
 replaceChildren(...items) { this.text = ''; this.children = items; }
 addEventListener(name, listener) { this.listeners[name] = listener; }
}
function setup(t) {
 const old = { document: globalThis.document, fetch: globalThis.fetch, setInterval: globalThis.setInterval };
 t.after(() => Object.assign(globalThis, old));
 const selectors = ['summary','source','published','confirmed','nodes','refresh'];
 const elements = Object.fromEntries(selectors.map(name => [name, new Element()]));
 const panel = { querySelector: selector => elements[selector.match(/data-policy-([a-z]+)/)[1]] };
 const listeners = {}; const requests = []; let interval;
 globalThis.document = { hidden: false, querySelector: () => panel, createElement: () => new Element(), addEventListener: (name, fn) => { listeners[name] = fn; } };
 globalThis.setInterval = callback => { interval = callback; return 1; };
 const data = { source_revision: 5, desired: { revision: 4 }, source: { available: true, current: false }, confirmed: 1, all_confirmed: false, nodes: [{ node_id: '<img src=x onerror=alert(1)>', role: 'worker', report: { applied: { revision: 4 }, desired: { revision: 4 } }, received_at: '2026-11-01T00:00:00Z', eligible: true, recent: true, confirmed: true }] };
 globalThis.fetch = async (url, options) => { requests.push({ url, options }); return { ok: true, json: async () => data }; };
 return { elements, data, requests, listeners, poll: () => interval() };
}
async function settle() { for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve)); }
test('new saved source stays pending even when nodes confirmed the older head; all text remains literal', async t => {
 const f = setup(t); initPolicySync(); await settle();
 assert.match(f.elements.summary.textContent, /awaiting publication/);
 assert.equal(f.elements.source.textContent, '5'); assert.equal(f.elements.published.textContent, 'v4');
 assert.equal(f.elements.nodes.children[0].children[0].text, '<img src=x onerror=alert(1)>');
 assert.equal(f.requests[0].url, '/rauthmgmt/policy-status'); assert.equal(f.requests[0].options.redirect, 'error'); assert.equal(f.requests[0].options.cache, 'no-store');
});
test('only explicit server confirmation shows success; failed refresh clears old confirmations', async t => {
 const f = setup(t); f.data.source.current = true; f.data.all_confirmed = true;
 initPolicySync(); await settle(); assert.match(f.elements.summary.textContent, /All assigned nodes confirmed/);
 globalThis.fetch = async () => { throw new Error('collector unavailable'); };
 f.poll(); await settle(); assert.match(f.elements.summary.textContent, /Unable to read/); assert.equal(f.elements.confirmed.textContent, '—'); assert.match(f.elements.nodes.textContent, /unavailable/);
});
test('legacy page without cluster panel makes no status request', async t => {
 setup(t); globalThis.document.querySelector = () => null; globalThis.fetch = async () => assert.fail('legacy status fetch'); initPolicySync(); await settle();
});
