// Change-password form: strength meter and confirmation match hint.
import { $ } from '../console/index.js';

const LEVELS = [
    { label: 'Weak', color: '#ef4444' },
    { label: 'Fair', color: '#f97316' },
    { label: 'Good', color: '#eab308' },
    { label: 'Strong', color: '#84cc16' },
    { label: 'Excellent', color: '#22c55e' }
];

// score is a rough 0-5 heuristic for feedback only; the server enforces policy.
function score(p) {
    if (!p) return 0;
    let s = 0;
    if (p.length >= 8) s++;
    if (p.length >= 14) s++;
    if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
    if (/\d/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.max(1, s);
}

export function initPasswordForm() {
    const form = $('#passwordForm');
    if (!form) return;
    const pass = $('#newPassword');
    const confirm = $('#confirmPassword');
    const bars = $('#strengthBar').children;
    const label = $('#strengthLabel');
    const hint = $('#matchHint');

    const renderStrength = () => {
        const s = score(pass.value);
        const level = LEVELS[s - 1];
        Array.from(bars).forEach((bar, i) => { bar.style.background = level && i < s ? level.color : ''; });
        label.textContent = level ? 'Strength: ' + level.label : '';
        label.style.color = level ? level.color : '';
    };

    const renderMatch = () => {
        if (!confirm.value) {
            hint.textContent = '';
            confirm.setCustomValidity('');
            return;
        }
        const same = confirm.value === pass.value;
        hint.textContent = same ? 'Passwords match' : 'Passwords do not match';
        hint.style.color = same ? 'var(--rc-ok)' : 'var(--rc-accent)';
        confirm.setCustomValidity(same ? '' : 'Passwords do not match');
    };

    pass.addEventListener('input', () => { renderStrength(); renderMatch(); });
    confirm.addEventListener('input', renderMatch);
}
