// Sidebar sections: [data-panel] blocks shown one at a time, synced with the
// URL hash so reloads, links and the back button keep the current section.
import { $, $$ } from './dom.js';
import { toast } from './toast.js';

let panels = [];
let navLinks = [];

function render(name) {
    if (!panels.length) return;
    const target = panels.find(p => p.dataset.panel === name) || panels[0];
    panels.forEach(p => { p.hidden = p !== target; });
    navLinks.forEach(a => {
        const active = a.dataset.nav === target.dataset.panel;
        a.classList.toggle('active', active);
        if (active) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    const title = $('#pageTitle');
    if (title && target.dataset.title) title.textContent = target.dataset.title;
    window.scrollTo({ top: 0 });
}

export function showSection(name) {
    if (location.hash !== '#' + name) history.pushState(null, '', '#' + name);
    render(name);
}

// initSections also turns a ?success=key redirect into a toast and opens the
// section that action belongs to (successSection) unless a hash is given.
export function initSections({ messages = {}, successSection = {} } = {}) {
    panels = $$('[data-panel]');
    navLinks = $$('[data-nav]');

    const go = (e, name) => { e.preventDefault(); showSection(name); };
    navLinks.forEach(a => a.addEventListener('click', (e) => go(e, a.dataset.nav)));
    $$('[data-goto]').forEach(el => el.addEventListener('click', (e) => go(e, el.dataset.goto)));
    window.addEventListener('popstate', () => render(location.hash.slice(1)));

    let initial = /^#[a-z0-9-]+$/.test(location.hash) ? location.hash.slice(1) : '';
    const success = new URLSearchParams(location.search).get('success');
    if (success) {
        toast(messages[success] || 'Done.');
        if (!initial && successSection[success]) initial = successSection[success];
        history.replaceState(null, '', location.pathname + (initial ? '#' + initial : ''));
    }
    render(initial);
}
