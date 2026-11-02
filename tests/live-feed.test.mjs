import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

class Element {
    constructor(tag = 'div') { this.tagName = tag; this.children = []; this.dataset = {}; this.hidden = false; this.value = ''; this.text = ''; this.listeners = new Map(); this.parent = null; }
    set textContent(value) { this.text = String(value); this.children = []; }
    get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
    set innerHTML(_) { throw new Error('Request content must never use innerHTML'); }
    append(...items) { for (const item of items) { if (item.tagName === 'fragment') this.append(...item.children); else { item.parent = this; this.children.push(item); } } }
    prepend(...items) { const expanded = items.flatMap(item => item.tagName === 'fragment' ? item.children : [item]); for (const item of expanded) item.parent = this; this.children.unshift(...expanded); }
    replaceChildren(...items) { this.children = []; this.text = ''; this.append(...items); }
    get lastElementChild() { return this.children.at(-1); }
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
    setAttribute(name, value) { this[name] = value; }
    addEventListener(name, callback) { this.listeners.set(name, callback); }
    fire(name) { this.listeners.get(name)?.({ target: this }); }
}

async function fixture() {
    const ids = ['liveFeedRows', 'liveFeedStatus', 'liveFeedCount', 'liveFeedEmpty', 'liveFeedNotice', 'liveFeedPause', 'liveFeedSearch', 'liveFeedAction', 'liveFeedNode'];
    const elements = new Map(ids.map(id => [`#${id}`, new Element()]));
    const panel = new Element(); const frames = [];
    class EventSource {
        static all = [];
        constructor(url) { this.url = url; this.handlers = new Map(); EventSource.all.push(this); }
        addEventListener(kind, callback) { this.handlers.set(kind, callback); }
        close() { this.closed = true; }
        emit(kind, data, id = '') { this.handlers.get(kind)?.({ data: JSON.stringify(data), lastEventId: id }); }
    }
    const document = { hidden: false, querySelector: selector => selector.includes('data-panel') ? panel : elements.get(selector) || null, createElement: tag => new Element(tag), createDocumentFragment: () => new Element('fragment'), addEventListener() {} };
    const context = vm.createContext({ document, window: { EventSource, addEventListener() {} }, EventSource, MutationObserver: class { observe() {} }, requestAnimationFrame: callback => { frames.push(callback); return frames.length; }, setTimeout: () => 1, clearTimeout() {}, console });
    const source = (await readFile(new URL('../static/js/management/live-feed.js', import.meta.url), 'utf8')).replace('export function initLiveFeed', 'function initLiveFeed');
    vm.runInContext(source + '\ninitLiveFeed();', context);
    return { elements, EventSource, stream: EventSource.all[0], flush() { for (const frame of frames.splice(0)) frame(); } };
}

const nodeA = '11111111-1111-4111-8111-111111111111';
const decision = { time: '2026-11-02T01:00:00Z', received_at: '2026-11-02T01:00:10Z', url: 'https://example.test/<img onerror=alert(1)>', source: '203.0.113.7', country: 'US', action: 'blocked', node_id: nodeA, node_name: '<worker-A>', reason: 'country_blocked' };

test('processing node and original source IP remain separate text-only cells', async () => {
    const f = await fixture(); f.stream.emit('request', decision, 'epoch:1'); f.flush();
    const row = f.elements.get('#liveFeedRows').children[0];
    const cells = new Map(row.children.map(cell => [cell.dataset.label, cell]));
    assert.equal(cells.get('Processing node').textContent, '<worker-A>');
    assert.equal(cells.get('Processing node').title, nodeA);
    assert.equal(cells.get('Source IP').textContent, '203.0.113.7');
    assert.equal(cells.get('URL').textContent, decision.url);
    assert.match(cells.get('Time').textContent, /Replayed/);
    assert.match(row.dataset.search, /worker-a/);
    assert.equal(f.elements.get('#liveFeedNode').children[0].value, nodeA);
});

test('processing-node filter restarts a bounded stream without old-node rows', async () => {
    const f = await fixture(); f.stream.emit('request', decision, 'epoch:1'); f.flush();
    const filter = f.elements.get('#liveFeedNode'); filter.value = nodeA; filter.fire('change');
    assert.equal(f.stream.closed, true);
    assert.equal(f.elements.get('#liveFeedRows').children.length, 0);
    assert.match(f.EventSource.all.at(-1).url, new RegExp(`node=${nodeA}`));
    f.stream.emit('request', decision, 'epoch:2'); f.flush();
    assert.equal(f.elements.get('#liveFeedRows').children.length, 0, 'old stream callbacks cannot add rows after filtering');
});

test('durable gap/checkpoint cursors survive pause and reconnect', async () => {
    const f = await fixture(); f.stream.emit('ready', { epoch: 'durable', cursor: 'durable:0' });
    f.stream.emit('gap', { loss_total: 7, node_name: 'worker-A' }, 'durable:2');
    assert.match(f.elements.get('#liveFeedNotice').textContent, /7 total/);
    f.stream.emit('cursor', { latest: 20 }, 'durable:20');
    const pause = f.elements.get('#liveFeedPause'); pause.fire('click'); pause.fire('click');
    assert.match(f.EventSource.all.at(-1).url, /after=durable%3A20/);
    f.EventSource.all.at(-1).emit('gap', { unknown_loss: true, node_name: 'worker-A' }, 'durable:21');
    assert.match(f.elements.get('#liveFeedNotice').textContent, /Possible loss.*worker-A/);
});
