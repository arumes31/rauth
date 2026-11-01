// Instant request decisions. Request-derived strings are inserted as text only.
const actions = new Map([
    ['authenticated', ['Allowed', 'ok']], ['bypass', ['Bypass', 'info']],
    ['login_required', ['Login required', 'warn']], ['blocked', ['Blocked', 'danger']],
    ['rate_limited', ['Rate limited', 'danger']], ['error', ['Error', 'danger']]
]);

export function initLiveFeed() {
    const panel = document.querySelector('[data-panel="live-feed"]');
    if (!panel) return;
    const rows = document.querySelector('#liveFeedRows');
    const status = document.querySelector('#liveFeedStatus');
    const count = document.querySelector('#liveFeedCount');
    const empty = document.querySelector('#liveFeedEmpty');
    const notice = document.querySelector('#liveFeedNotice');
    const pause = document.querySelector('#liveFeedPause');
    const search = document.querySelector('#liveFeedSearch');
    const filter = document.querySelector('#liveFeedAction');
    let stream = null, cursor = '', paused = false, ended = false;
    let retry = null, retryDelay = 1000, frame = null, pending = [];
    const active = () => !panel.hidden && !document.hidden && !paused && !ended;
    const showStatus = (text, kind) => { status.textContent = text; status.className = `chip ${kind}`; };
    const showNotice = text => { notice.textContent = text; notice.hidden = !text; };
    const parse = event => { try { return JSON.parse(event.data); } catch (_) { return null; } };

    function applyFilter() {
        const query = search.value.trim().toLowerCase();
        let shown = 0;
        for (const row of rows.children) {
            row.hidden = (filter.value && row.dataset.action !== filter.value) || !row.dataset.search.includes(query);
            if (!row.hidden) shown++;
        }
        count.textContent = `${shown} of ${rows.children.length} recent decisions`;
        empty.hidden = shown > 0;
        empty.textContent = rows.children.length ? 'No matching requests' : 'Waiting for requests';
    }

    function rowFor(event) {
        const row = document.createElement('tr');
        const [label, kind] = actions.get(event.action) || actions.get('error');
        const country = typeof event.country === 'string' ? event.country : 'unknown';
        const url = typeof event.url === 'string' ? event.url : '';
        const source = typeof event.source === 'string' ? event.source : 'unknown';
        row.dataset.action = actions.has(event.action) ? event.action : 'error';
        row.dataset.search = [url, source, country, label].join(' ').toLowerCase();
        const cell = (name, text, cls = '') => {
            const td = document.createElement('td');
            td.dataset.label = name; td.className = cls; td.textContent = text;
            row.append(td); return td;
        };
        const time = new Date(event.time);
        const timeCell = cell('Time', '', 'text-muted small text-nowrap');
        const timeNode = document.createElement('time');
        if (Number.isFinite(time.getTime())) {
            timeNode.dateTime = time.toISOString(); timeNode.textContent = time.toLocaleTimeString();
            timeNode.title = time.toLocaleString();
        } else timeNode.textContent = 'Unknown';
        timeCell.append(timeNode);
        cell('URL', url || 'Not provided by a trusted proxy', 'mono small live-feed-url');
        cell('Source IP', source, 'mono small');
        cell('Country', country, 'small');
        const action = cell('Action', '');
        const chip = document.createElement('span'); chip.className = `chip ${kind}`; chip.textContent = label;
        action.append(chip);
        return row;
    }

    function flush() {
        frame = null;
        const fragment = document.createDocumentFragment();
        for (const event of pending) fragment.prepend(rowFor(event));
        pending = []; rows.prepend(fragment);
        while (rows.children.length > 300) rows.lastElementChild.remove();
        applyFilter();
    }

    function close() {
        if (stream) { stream.close(); stream = null; }
        clearTimeout(retry); retry = null;
    }

    function connect() {
        if (!active() || stream || !window.EventSource) return;
        showStatus('Connecting', 'info');
        const source = new EventSource('/rauthmgmt/live-feed' + (cursor ? `?after=${encodeURIComponent(cursor)}` : ''));
        stream = source;
        source.addEventListener('ready', event => {
            if (stream !== source) return;
            const state = parse(event);
            if (!cursor && typeof state?.cursor === 'string') cursor = state.cursor;
            retryDelay = 1000; showStatus('Live', 'ok');
        });
        source.addEventListener('request', event => {
            if (stream !== source) return;
            const data = parse(event);
            if (!data || typeof data !== 'object' || !/^[-a-z0-9]+:\d+$/.test(event.lastEventId)) return;
            if (cursor === event.lastEventId) return;
            cursor = event.lastEventId; pending.push(data);
            if (pending.length > 300) { pending.shift(); showNotice('Only the newest requests in this burst are shown.'); }
            if (frame === null) frame = requestAnimationFrame(flush);
        });
        source.addEventListener('reset', event => {
            if (stream !== source) return;
            const state = parse(event);
            cursor = typeof state?.cursor === 'string' ? state.cursor : '';
            pending = []; rows.replaceChildren(); applyFilter();
            showNotice('RAuth restarted. Showing the latest available decisions.');
        });
        source.addEventListener('gap', event => {
            if (stream !== source) return;
            const data = parse(event);
            showNotice(`${Number(data?.dropped) || 0} older decisions expired while disconnected. Showing available requests.`);
        });
        source.addEventListener('session-ended', () => {
            if (stream !== source) return;
            ended = true; close(); showStatus('Access ended', 'danger');
            showNotice('Your session or administrator access ended. Reload to sign in again.');
        });
        source.onerror = () => {
            if (stream !== source) return;
            close(); showStatus('Reconnecting', 'warn');
            if (active()) { retry = setTimeout(connect, retryDelay); retryDelay = Math.min(30000, retryDelay * 2); }
        };
    }

    function syncConnection() {
        if (active()) connect();
        else { close(); if (!ended) showStatus(paused ? 'Paused' : 'Suspended', 'info'); }
    }
    pause.addEventListener('click', () => {
        paused = !paused; pause.textContent = paused ? 'Resume' : 'Pause';
        pause.setAttribute('aria-pressed', String(paused)); syncConnection();
    });
    search.addEventListener('input', applyFilter); filter.addEventListener('change', applyFilter);
    new MutationObserver(syncConnection).observe(panel, { attributes: true, attributeFilter: ['hidden'] });
    document.addEventListener('visibilitychange', syncConnection);
    window.addEventListener('pagehide', close);
    if (!window.EventSource) { ended = true; showStatus('Unsupported browser', 'warn'); }
    else syncConnection();
}
