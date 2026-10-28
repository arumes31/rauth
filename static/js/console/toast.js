// Transient notifications in the bottom-right corner.

const ICONS = { success: 'bi-check-circle-fill', error: 'bi-x-octagon-fill', info: 'bi-info-circle-fill' };

function host() {
    let el = document.getElementById('toastHost');
    if (!el) {
        el = document.createElement('div');
        el.id = 'toastHost';
        el.className = 'toast-host';
        el.setAttribute('aria-live', 'polite');
        document.body.appendChild(el);
    }
    return el;
}

export function toast(message, variant = 'success') {
    const el = document.createElement('div');
    el.className = 'rauth-toast ' + variant;
    el.innerHTML = `<i class="bi ${ICONS[variant] || ICONS.info}"></i><span></span><button type="button" class="btn-close btn-close-white" aria-label="Close"></button>`;
    el.querySelector('span').textContent = message;
    const remove = () => { el.classList.remove('visible'); setTimeout(() => el.remove(), 250); };
    el.querySelector('button').addEventListener('click', remove);
    host().appendChild(el);
    requestAnimationFrame(() => el.classList.add('visible'));
    setTimeout(remove, 5000);
}
