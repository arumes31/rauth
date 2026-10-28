// Management console (/rauthmgmt).
import { $, $$, alertDialog, initConsole, setFieldValue, showModal, showSection } from './console/index.js';

const messages = {
    '2fa_reset': 'Two-factor authentication was reset for the user.',
    'password_changed': 'The user\'s password was updated.',
    'email_updated': 'The user\'s email address was updated.',
    'user_created': 'User created.',
    'user_deleted': 'User deleted.',
    'session_terminated': 'Session ended.',
    'bypass_added': 'Public access rule added.',
    'bypass_deleted': 'Public access rule removed.',
    'bypass_updated': 'Public access rule updated.',
    'bypass_unlocked': 'Public access changes unlocked for 15 minutes.',
    'bypass_locked': 'Public access changes locked.'
};

const successSection = {
    '2fa_reset': 'users', 'password_changed': 'users', 'email_updated': 'users',
    'user_created': 'users', 'user_deleted': 'users', 'session_terminated': 'sessions',
    'bypass_added': 'bypass', 'bypass_deleted': 'bypass', 'bypass_updated': 'bypass',
    'bypass_unlocked': 'bypass', 'bypass_locked': 'bypass'
};

function showAuditKind(kind) {
    setFieldValue($('#auditKind'), kind);
    showSection('audit');
}

function showSessionsFor(username) {
    setFieldValue($('#sessionSearch'), username);
    showSection('sessions');
}

const commands = [
    { name: 'Go to Overview', cmd: 'overview', icon: 'bi-grid-1x2', run: () => showSection('overview') },
    { name: 'Go to Users', cmd: 'users', icon: 'bi-people', run: () => showSection('users') },
    { name: 'Go to Sessions', cmd: 'sessions', icon: 'bi-broadcast', run: () => showSection('sessions') },
    { name: 'Go to Invitations', cmd: 'invites', icon: 'bi-envelope-plus', run: () => showSection('invites') },
    { name: 'Go to Public Access', cmd: 'public', icon: 'bi-globe2', run: () => showSection('bypass') },
    { name: 'Go to Audit Log', cmd: 'audit', icon: 'bi-journal-text', run: () => showSection('audit') },
    { name: 'Add user', cmd: 'new', icon: 'bi-person-plus', run: () => showModal('createUserModal') },
    { name: 'Show failed sign-ins', cmd: 'failed', icon: 'bi-exclamation-octagon', run: () => showAuditKind('bad') },
    { name: 'My profile', cmd: 'profile', icon: 'bi-person-circle', run: () => { location.href = '/rauthprofile'; } },
    { name: 'Sign out', cmd: 'logout', icon: 'bi-box-arrow-right', run: () => $('form[action="/logout"]').submit() }
];

// Hide the "all clear" row when something needs attention.
function initAttentionList() {
    const list = $('[data-panel="overview"] .checklist');
    if (list && $$('li:not(.all-clear)', list).length) $('.all-clear', list).remove();
    $$('[data-audit-filter]').forEach(btn => btn.addEventListener('click', () => showAuditKind(btn.dataset.auditFilter)));
}

// Edit user modal, filled from the clicked row's data attributes.
function initUserEditor() {
    const modal = $('#editUserModal');
    $$('[data-edit-user]').forEach(btn => btn.addEventListener('click', () => {
        const u = btn.dataset.username;
        const sessions = parseInt(btn.dataset.sessions || '0', 10);
        const has2fa = btn.dataset.has2fa === '1';

        $('#editUserTitle').textContent = u;
        $('#editUserMeta').textContent = `${btn.dataset.email || 'No email'} · ${sessions} active session(s)`;
        $('#editUserAvatar').src = $(`img[data-identicon="${CSS.escape(u)}"]`)?.src || '';
        ['#emailUsernameInput', '#passwordUsernameInput', '#reset2faUsernameInput'].forEach(id => { $(id).value = u; });
        $('#emailInput').value = btn.dataset.email || '';
        $('#adminNewPassword').value = '';

        const chip = $('#edit2faChip');
        chip.className = 'chip ms-1 ' + (has2fa ? 'ok' : 'warn');
        chip.textContent = has2fa ? 'Enabled' : 'Not set up';
        $('#reset2faBtn').disabled = !has2fa;

        bootstrap.Tab.getOrCreateInstance($('[data-bs-target="#editTabEmail"]', modal)).show();
        showModal('editUserModal');
    }));

    $$('[data-sessions-for]').forEach(btn => btn.addEventListener('click', () => showSessionsFor(btn.dataset.sessionsFor)));
}

function initBypassEditor() {
    $$('.bypass-edit').forEach(btn => btn.addEventListener('click', () => {
        $('#editBypassOriginal').value = btn.dataset.rule;
        $('#editBypassRule').value = btn.dataset.rule;
        $('#editBypassAction').value = btn.dataset.action;
        $('#editBypassNote').value = btn.dataset.note || '';
        showModal('editBypassModal');
    }));
}

// Invitations are created over fetch so the link can be copied right away.
function initInvites() {
    const form = $('#inviteForm');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const submit = $('#inviteSubmit');
        submit.disabled = true;
        try {
            const response = await fetch('/rauthmgmt/invite/create', { method: 'POST', body: new FormData(form) });
            if (!response.ok) {
                let msg = 'The server rejected the request.';
                try { const j = await response.json(); msg = j.message || j.error || msg; } catch (_) { /* not JSON */ }
                alertDialog({ title: 'Invitation failed', message: msg, icon: 'bi-envelope-x', variant: 'danger' });
                return;
            }
            const data = await response.json();
            $('#inviteUrl').value = data.url;
            $('#inviteFor').textContent = $('#inviteEmail').value;
            $('#inviteResult').hidden = false;
            form.reset();
        } catch (_) {
            alertDialog({ title: 'Network error', message: 'Could not reach the server. Please try again.', icon: 'bi-wifi-off', variant: 'danger' });
        } finally {
            submit.disabled = false;
        }
    });
}

initConsole({ messages, successSection, commands });
initAttentionList();
initUserEditor();
initBypassEditor();
initInvites();
