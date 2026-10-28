// Promise-based confirm / alert / prompt dialogs replacing the native ones,
// plus wiring for forms that carry data-confirm.
import { escapeHtml, $$ } from './dom.js';
import { submitForm } from './forms.js';

let dialogSeq = 0;

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';

// keepFocusInside wraps Tab / Shift+Tab around the dialog's controls.
function keepFocusInside(e, overlay) {
    const items = $$(FOCUSABLE, overlay);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    const inside = overlay.contains(document.activeElement);
    if (e.shiftKey && (document.activeElement === first || !inside)) {
        e.preventDefault();
        last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !inside)) {
        e.preventDefault();
        first.focus();
    }
}

function open(html, ids, onKey) {
    const opener = document.activeElement;
    const overlay = document.createElement('div');
    overlay.className = 'rauth-dialog-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', ids.title);
    overlay.setAttribute('aria-describedby', ids.message);
    overlay.innerHTML = html;
    document.body.appendChild(overlay);
    requestAnimationFrame(() => requestAnimationFrame(() => overlay.classList.add('visible')));

    const keyHandler = (e) => {
        if (e.key === 'Tab') keepFocusInside(e, overlay);
        else onKey(e);
    };
    document.addEventListener('keydown', keyHandler);
    return {
        overlay,
        close() {
            document.removeEventListener('keydown', keyHandler);
            overlay.classList.remove('visible');
            setTimeout(() => overlay.remove(), 200);
            if (opener && typeof opener.focus === 'function' && document.contains(opener)) opener.focus();
        }
    };
}

function frame({ title, message, icon, variant }, ids, extra, actions) {
    return `
        <div class="rauth-dialog">
            <div class="rauth-dialog-head">
                <div class="rauth-dialog-icon ${escapeHtml(variant)}" aria-hidden="true"><i class="bi ${escapeHtml(icon)}"></i></div>
                <div>
                    <div class="rauth-dialog-title" id="${ids.title}">${escapeHtml(title)}</div>
                    <div class="rauth-dialog-message" id="${ids.message}">${escapeHtml(message)}</div>
                </div>
            </div>
            ${extra}
            <div class="rauth-dialog-actions">${actions}</div>
        </div>`;
}

// show opens a dialog and resolves with what the clicked action returns.
// actions maps data-action names to result functions. Escape and clicking the
// backdrop run "cancel"; Enter in the prompt input runs "primary". Enter on a
// focused button is left to the button itself, so Enter on Cancel cancels.
function show(opts, extra, buttons, actions) {
    return new Promise((resolve) => {
        const n = ++dialogSeq;
        const ids = { title: `rauthDialogTitle${n}`, message: `rauthDialogMessage${n}` };
        let dlg;
        const finish = (name) => { dlg.close(); resolve(actions[name] ? actions[name](dlg.overlay) : undefined); };
        dlg = open(frame(opts, ids, extra, buttons), ids, (e) => {
            if (e.key === 'Escape') { e.preventDefault(); finish('cancel'); }
            if (e.key === 'Enter' && e.target.matches?.('.rauth-dialog input')) { e.preventDefault(); finish('primary'); }
        });
        dlg.overlay.querySelectorAll('[data-action]').forEach(btn => {
            btn.addEventListener('click', () => finish(btn.dataset.action));
        });
        dlg.overlay.addEventListener('click', (e) => { if (e.target === dlg.overlay) finish('cancel'); });
        (dlg.overlay.querySelector('input') || dlg.overlay.querySelector('[data-action="primary"]')).focus();
        dlg.overlay.querySelector('input')?.select();
    });
}

export function confirmDialog({ title = 'Confirm action', message = 'Are you sure?', icon = 'bi-exclamation-triangle', variant = 'danger', confirmText = 'Confirm', cancelText = 'Cancel' } = {}) {
    const btnClass = variant === 'warning' ? 'btn-warning' : 'btn-danger';
    return show({ title, message, icon, variant }, '',
        `<button type="button" class="btn btn-ghost" data-action="cancel">${escapeHtml(cancelText)}</button>
         <button type="button" class="btn ${btnClass}" data-action="primary">${escapeHtml(confirmText)}</button>`,
        { primary: () => true, cancel: () => false });
}

export function alertDialog({ title = 'Notice', message = '', icon = 'bi-info-circle', variant = 'info' } = {}) {
    return show({ title, message, icon, variant }, '',
        '<button type="button" class="btn btn-primary" data-action="primary">OK</button>',
        {});
}

export function promptDialog({ title = 'Input required', message = '', icon = 'bi-pencil-square', variant = 'info', placeholder = '', defaultValue = '', confirmText = 'Save' } = {}) {
    const value = (overlay) => overlay.querySelector('input').value;
    return show({ title, message, icon, variant },
        `<div class="rauth-dialog-field"><input type="text" class="form-control" aria-label="${escapeHtml(title)}" placeholder="${escapeHtml(placeholder)}" value="${escapeHtml(defaultValue)}" maxlength="64"></div>`,
        `<button type="button" class="btn btn-ghost" data-action="cancel">Cancel</button>
         <button type="button" class="btn btn-primary" data-action="primary">${escapeHtml(confirmText)}</button>`,
        { primary: value, cancel: () => null });
}

// Forms with data-confirm ask first, then submit (with fetch if data-async).
export function initConfirmForms(root = document) {
    $$('form[data-confirm]', root).forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!form.reportValidity()) return;
            const ok = await confirmDialog({
                title: form.dataset.confirmTitle || 'Confirm action',
                message: form.dataset.confirm,
                icon: form.dataset.confirmIcon || 'bi-exclamation-triangle',
                variant: form.dataset.confirmVariant || 'danger',
                confirmText: form.dataset.confirmBtn || 'Confirm'
            });
            if (ok) submitForm(form);
        });
    });
}
