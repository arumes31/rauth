// Passkey registration, rename and removal. Adding or removing a passkey
// needs the step-up value (TOTP code or current password) from #passkeyStepup.
import { $, $$, alertDialog, confirmDialog, csrfToken, promptDialog } from '../console/index.js';

function setMessage(text, tone) {
    const msg = $('#passkeyMessage');
    msg.textContent = text;
    msg.className = 'small mt-2 ' + ({ ok: 'text-success', error: 'text-danger', busy: 'text-muted' }[tone] || '');
}

// requireStepup returns the step-up input value, or null after telling the user.
async function requireStepup() {
    const input = $('#passkeyStepup');
    if (input.value.trim()) return input;
    await alertDialog({
        title: 'Confirmation required',
        message: input.dataset.stepupName === 'otp_code'
            ? 'Enter your authenticator code first.'
            : 'Enter your current password first.',
        icon: 'bi-shield-lock',
        variant: 'warning'
    });
    input.focus();
    return null;
}

async function errorText(response, fallback) {
    try {
        const j = await response.json();
        return j.message || j.error || fallback;
    } catch (_) {
        return fallback;
    }
}

async function register() {
    const stepup = await requireStepup();
    if (!stepup) return;
    const btn = $('#registerPasskey');
    btn.disabled = true;
    try {
        setMessage('Requesting a challenge from the server…', 'busy');
        const begin = await fetch('/webauthn/register/begin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrfToken() },
            body: new URLSearchParams({ [stepup.dataset.stepupName]: stepup.value })
        });
        if (!begin.ok) {
            setMessage(await errorText(begin, 'Verification failed.'), 'error');
            return;
        }
        const optionsJSON = await begin.json();

        setMessage('Follow the prompt from your browser or security key…', 'busy');
        const credential = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });

        setMessage('Verifying with the server…', 'busy');
        const finish = await fetch('/webauthn/register/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
            body: JSON.stringify(credential)
        });
        if (!finish.ok) {
            setMessage(await errorText(finish, 'The server rejected the passkey.'), 'error');
            return;
        }
        setMessage('Passkey added.', 'ok');
        setTimeout(() => location.reload(), 1000);
    } catch (e) {
        setMessage(e.name === 'NotAllowedError' ? 'Cancelled or timed out.' : 'Error: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
    }
}

export function initPasskeys() {
    $('#registerPasskey')?.addEventListener('click', register);

    $$('[data-rename-passkey]').forEach(btn => btn.addEventListener('click', async () => {
        const name = await promptDialog({
            title: 'Rename passkey',
            message: 'Choose a name that helps you recognise this key.',
            placeholder: 'e.g. YubiKey 5, MacBook Touch ID',
            defaultValue: btn.dataset.passkeyName
        });
        if (!name || !name.trim()) return;
        const form = document.getElementById('rename-form-' + btn.dataset.renamePasskey);
        form.elements.nickname.value = name.trim();
        form.submit();
    }));

    $$('form.passkey-revoke').forEach(form => form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const stepup = await requireStepup();
        if (!stepup) return;
        const ok = await confirmDialog({
            title: 'Remove passkey?',
            message: `"${form.dataset.passkeyName}" will no longer be able to sign in to your account.`,
            icon: 'bi-key',
            confirmText: 'Remove'
        });
        if (!ok) return;
        form.querySelector('[data-passkey-stepup]').value = stepup.value;
        HTMLFormElement.prototype.submit.call(form);
    }));
}
