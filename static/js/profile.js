// Profile console (/rauthprofile).
import { $, initConsole, showSection } from './console/index.js';
import { initPasskeys } from './profile/passkeys.js';
import { initPasswordForm } from './profile/password.js';

const messages = {
    'sessions_terminated': 'All other devices were signed out.',
    'session_terminated': 'The device was signed out.',
    'password_changed': 'Password updated.',
    'totp_disabled': 'Two-factor authentication disabled.',
    'passkey_renamed': 'Passkey renamed.',
    'passkey_revoked': 'Passkey removed.',
    'recovery_generated': 'New recovery codes generated.'
};

const successSection = {
    'sessions_terminated': 'sessions', 'session_terminated': 'sessions',
    'password_changed': 'security', 'totp_disabled': 'security',
    'passkey_renamed': 'security', 'passkey_revoked': 'security', 'recovery_generated': 'security'
};

const commands = [
    { name: 'Go to Overview', cmd: 'overview', icon: 'bi-person-badge', run: () => showSection('overview') },
    { name: 'Change password', cmd: 'password', icon: 'bi-key', run: () => { showSection('security'); $('#currentPassword').focus(); } },
    { name: 'Add passkey', cmd: 'passkey', icon: 'bi-fingerprint', run: () => { showSection('security'); $('#passkeyStepup').focus(); } },
    { name: 'Signed-in devices', cmd: 'sessions', icon: 'bi-laptop', run: () => showSection('sessions') },
    { name: 'Security activity', cmd: 'activity', icon: 'bi-clock-history', run: () => showSection('activity') },
    ...($('a[href="/rauthmgmt"]') ? [{ name: 'Admin console', cmd: 'admin', icon: 'bi-speedometer2', run: () => { location.href = '/rauthmgmt'; } }] : []),
    { name: 'Sign out', cmd: 'logout', icon: 'bi-box-arrow-right', run: () => $('form[action="/logout"]').submit() }
];

initConsole({ messages, successSection, commands });
initPasswordForm();
initPasskeys();
