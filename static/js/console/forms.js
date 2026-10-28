// Forms marked data-async are posted with fetch so a failure shows the
// server's message in place instead of leaving the console for an error page
// or a bare JSON body. On success the browser follows the handler's redirect;
// a handler that answers with a page directly (recovery codes) is shown as is.
import { $$ } from './dom.js';
import { toast } from './toast.js';

async function errorMessage(response) {
    try {
        const data = await response.clone().json();
        if (data && (data.error || data.message)) return data.error || data.message;
    } catch (_) { /* not JSON */ }
    return response.status === 429 ? 'Too many attempts. Please try again later.' : `Request failed (${response.status}).`;
}

async function submitAsync(form) {
    const buttons = $$('button[type="submit"], button:not([type])', form);
    buttons.forEach(b => { b.disabled = true; });
    try {
        const response = await fetch(form.action, {
            method: 'POST',
            // URL-encoded like a native submit (these forms carry no files).
            body: new URLSearchParams(new FormData(form)),
            headers: { Accept: 'application/json' },
            credentials: 'same-origin'
        });
        if (!response.ok) {
            toast(await errorMessage(response), 'error');
            return;
        }
        if (response.redirected) {
            location.assign(response.url);
            return;
        }
        // A rendered page (e.g. freshly generated recovery codes) replaces the console.
        const html = await response.text();
        document.open();
        document.write(html);
        document.close();
    } catch (_) {
        toast('Could not reach the server. Please try again.', 'error');
    } finally {
        buttons.forEach(b => { b.disabled = false; });
    }
}

// submitForm posts a form the way it asks for: with fetch when it carries
// data-async, otherwise as a normal navigation.
export function submitForm(form) {
    if (form.hasAttribute('data-async')) return submitAsync(form);
    // Call the prototype so an input named "submit" cannot shadow it.
    HTMLFormElement.prototype.submit.call(form);
    return Promise.resolve();
}

// Async forms without a confirmation step submit directly; confirm forms and
// script-driven forms route through submitForm themselves.
export function initAsyncForms(root = document) {
    $$('form[data-async]:not([data-confirm]):not([data-managed])', root).forEach(form => {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            if (form.reportValidity()) submitForm(form);
        });
    });
}
