// Promise-based confirm / alert / prompt dialogs replacing the native ones,
// plus wiring for forms that carry data-confirm.
import { escapeHtml, $$ } from './dom.js';

function open(html, onKey) {
    const overlay = document.createElement('div');
    overlay.className = 'rauth-dialog-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.innerHTML = html;
    document.body.appendChild(overlay);
    requestAnimationFrame(() => requestAnimationFrame(() => overlay.classList.add('visible')));
    document.addEventListener('keydown', onKey);
    return {
        overlay,
        close() {
            document.removeEventListener('keydown', onKey);
            overlay.classList.remove('visible');
            setTimeout(() => overlay.remove(), 200);
        }
    };
}

function frame({ title, message, icon, variant }, extra, actions) {
    return `
        <div class="rauth-dialog">
            <div class="rauth-dialog-head">
                <div class="rauth-dialog-icon ${escapeHtml(variant)}"><i class="bi ${escapeHtml(icon)}"></i></div>
                <div>
                    <div class="rauth-dialog-title">${escapeHtml(title)}</div>
                    <div class="rauth-dialog-message">${escapeHtml(message)}</div>
                </div>
            </div>
            ${extra}
            <div class="rauth-dialog-actions">${actions}</div>
        </div>`;
}

// show opens a dialog and resolves with what the clicked action returns.
// actions maps data-action names to result functions; Enter runs the
// "primary" action, Escape and clicking the backdrop run "cancel".
function show(opts, extra, buttons, actions) {
    return new Promise((resolve) => {
        let dlg;
        const finish = (name) => { dlg.close(); resolve(actions[name] ? actions[name](dlg.overlay) : undefined); };
        dlg = open(frame(opts, extra, buttons), (e) => {
            if (e.key === 'Escape') { e.preventDefault(); finish('cancel'); }
            if (e.key === 'Enter') { e.preventDefault(); finish('primary'); }
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
        `<button class="btn btn-ghost" data-action="cancel">${escapeHtml(cancelText)}</button>
         <button class="btn ${btnClass}" data-action="primary">${escapeHtml(confirmText)}</button>`,
        { primary: () => true, cancel: () => false });
}

export function alertDialog({ title = 'Notice', message = '', icon = 'bi-info-circle', variant = 'info' } = {}) {
    return show({ title, message, icon, variant }, '',
        '<button class="btn btn-primary" data-action="primary">OK</button>',
        {});
}

export function promptDialog({ title = 'Input required', message = '', icon = 'bi-pencil-square', variant = 'info', placeholder = '', defaultValue = '', confirmText = 'Save' } = {}) {
    const value = (overlay) => overlay.querySelector('input').value;
    return show({ title, message, icon, variant },
        `<div class="rauth-dialog-field"><input type="text" class="form-control" placeholder="${escapeHtml(placeholder)}" value="${escapeHtml(defaultValue)}" maxlength="64"></div>`,
        `<button class="btn btn-ghost" data-action="cancel">Cancel</button>
         <button class="btn btn-primary" data-action="primary">${escapeHtml(confirmText)}</button>`,
        { primary: value, cancel: () => null });
}

// Forms with data-confirm ask first, then submit for real.
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
            // Call the prototype so an input named "submit" cannot shadow it.
            if (ok) HTMLFormElement.prototype.submit.call(form);
        });
    });
}
