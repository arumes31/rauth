// Client-side table filters.
//
//   <input data-filter="#table">        free-text match on rows' data-search
//   <select data-filter-kind="#table">  match a word in rows' data-kind
//   <span data-filter-count="#table">   number of visible rows
//   <tr data-filter-empty>              shown when nothing matches
import { $, $$ } from './dom.js';

function apply(sel) {
    const target = $(sel);
    if (!target) return;
    const text = $(`[data-filter="${sel}"]`);
    const kind = $(`[data-filter-kind="${sel}"]`);
    const term = text ? text.value.trim().toLowerCase() : '';
    const k = kind ? kind.value : '';
    let shown = 0;
    $$('[data-row]', target).forEach(row => {
        const hay = (row.dataset.search || row.textContent).toLowerCase();
        const kinds = (row.dataset.kind || '').split(/\s+/);
        const visible = (!term || hay.includes(term)) && (!k || kinds.includes(k));
        row.hidden = !visible;
        if (visible) shown++;
    });
    const empty = $('[data-filter-empty]', target);
    if (empty) empty.hidden = shown !== 0;
    const counter = $(`[data-filter-count="${sel}"]`);
    if (counter) counter.textContent = shown;
}

export function initFilters() {
    $$('[data-filter], [data-filter-kind]').forEach(el => {
        const sel = el.dataset.filter || el.dataset.filterKind;
        el.addEventListener('input', () => apply(sel));
        el.addEventListener('change', () => apply(sel));
    });
}
