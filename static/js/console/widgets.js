// Declarative widgets enabled by data attributes:
//
//   <img data-identicon="name">        deterministic avatar
//   <time data-ts="unix">              relative time, absolute in the tooltip
//   <button data-reveal="#input">      show/hide a password field
//   <button data-generate="#input">    fill a strong random password
//   <button data-copy="#input">        copy a field to the clipboard
//   <tr data-details="{json}">         open the JSON in #detailModal
import { $, $$, showModal } from './dom.js';

function identicon(str, size) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) hash = str.charCodeAt(i) + ((hash << 5) - hash);
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = size;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#18181c';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = `hsl(${Math.abs(hash % 360)}, 65%, 58%)`;
    const n = 5, cell = size / n;
    for (let i = 0; i < n; i++) {
        for (let j = 0; j < n; j++) {
            if ((Math.abs(hash) >> (i * n + j)) & 1) {
                ctx.fillRect(i * cell, j * cell, cell, cell);
                ctx.fillRect((n - 1 - i) * cell, j * cell, cell, cell);
            }
        }
    }
    return canvas.toDataURL();
}

const UNITS = [[60, 'second', 1], [3600, 'minute', 60], [86400, 'hour', 3600], [2592000, 'day', 86400], [31536000, 'month', 2592000], [Infinity, 'year', 31536000]];

function relTime(ts) {
    const diff = Math.round(Date.now() / 1000 - ts);
    const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
    for (const [limit, unit, div] of UNITS) {
        if (Math.abs(diff) < limit) return rtf.format(-Math.round(diff / div), unit);
    }
    return '';
}

const EYE = '<i class="bi bi-eye"></i>';
const EYE_OFF = '<i class="bi bi-eye-slash"></i>';
const PASSWORD_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_=+';

function setRevealed(input, shown) {
    input.type = shown ? 'text' : 'password';
    const btn = $(`[data-reveal="#${CSS.escape(input.id)}"]`);
    if (btn) {
        btn.innerHTML = shown ? EYE_OFF : EYE;
        btn.setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
    }
}

export function initWidgets() {
    $$('img[data-identicon]').forEach(el => {
        el.src = identicon(el.dataset.identicon || '?', 64);
        el.alt = '';
    });

    $$('time[data-ts]').forEach(el => {
        const ts = parseInt(el.dataset.ts, 10);
        if (!ts) return;
        const d = new Date(ts * 1000);
        el.title = d.toLocaleString();
        el.dateTime = d.toISOString();
        el.textContent = relTime(ts);
    });

    $$('[data-reveal]').forEach(btn => btn.addEventListener('click', () => {
        const input = $(btn.dataset.reveal);
        if (input) setRevealed(input, input.type === 'password');
    }));

    $$('[data-generate]').forEach(btn => btn.addEventListener('click', () => {
        const input = $(btn.dataset.generate);
        if (!input) return;
        const bytes = new Uint32Array(20);
        crypto.getRandomValues(bytes);
        input.value = Array.from(bytes, b => PASSWORD_ALPHABET[b % PASSWORD_ALPHABET.length]).join('');
        input.dispatchEvent(new Event('input'));
        setRevealed(input, true);
        input.select();
    }));

    $$('[data-copy]').forEach(btn => btn.addEventListener('click', async () => {
        const input = $(btn.dataset.copy);
        if (!input) return;
        try {
            await navigator.clipboard.writeText(input.value);
        } catch (_) {
            input.select();
            document.execCommand('copy');
        }
        const html = btn.innerHTML;
        btn.innerHTML = '<i class="bi bi-check2 me-1"></i>Copied';
        setTimeout(() => { btn.innerHTML = html; }, 1800);
    }));

    $$('[data-details]').forEach(row => {
        const open = () => {
            let pretty = row.dataset.details;
            try { pretty = JSON.stringify(JSON.parse(pretty), null, 2); } catch (_) { /* show raw */ }
            $('#detailBody').textContent = pretty;
            $('#detailTitle').textContent = row.dataset.detailsTitle || 'Event details';
            showModal('detailModal');
        };
        row.addEventListener('click', open);
        row.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
        });
    });
}
