// Command palette opened with Ctrl/Cmd+K, "/" or [data-open-palette].
// commands: [{ name, cmd, icon, run }]
import { $, $$, escapeHtml } from './dom.js';

export function initPalette(commands) {
    const el = $('#commandPalette');
    if (!el || !commands?.length) return;
    const modal = new bootstrap.Modal(el);
    const input = $('#commandInput');
    const results = $('#commandResults');
    let focus = 0;
    let filtered = [];

    const run = (c) => { modal.hide(); setTimeout(() => c.run(), 150); };

    const render = () => {
        const q = input.value.trim().toLowerCase();
        filtered = commands.filter(c => !q || c.name.toLowerCase().includes(q) || c.cmd.includes(q));
        results.innerHTML = filtered.length ? '' : '<div class="command-empty">No matching command</div>';
        filtered.forEach((c, i) => {
            const opt = document.createElement('div');
            opt.className = 'command-option' + (i === focus ? ' active' : '');
            opt.setAttribute('role', 'option');
            opt.innerHTML = `<span><i class="bi ${escapeHtml(c.icon || 'bi-chevron-right')} me-2"></i>${escapeHtml(c.name)}</span><span class="kbd">${escapeHtml(c.cmd)}</span>`;
            opt.addEventListener('click', () => run(c));
            results.appendChild(opt);
        });
    };

    const move = (delta) => {
        if (!filtered.length) return;
        focus = (focus + delta + filtered.length) % filtered.length;
        render();
        results.children[focus]?.scrollIntoView({ block: 'nearest' });
    };

    document.addEventListener('keydown', (e) => {
        const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName);
        if (((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') || (e.key === '/' && !typing)) {
            e.preventDefault();
            modal.show();
        }
    });
    $$('[data-open-palette]').forEach(b => b.addEventListener('click', () => modal.show()));
    // Reset on close rather than on open so nothing typed while it opens is lost.
    el.addEventListener('show.bs.modal', render);
    el.addEventListener('shown.bs.modal', () => input.focus());
    el.addEventListener('hidden.bs.modal', () => { input.value = ''; focus = 0; });
    input.addEventListener('input', () => { focus = 0; render(); });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
        if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
        if (e.key === 'Enter') { e.preventDefault(); if (filtered[focus]) run(filtered[focus]); }
    });
}
