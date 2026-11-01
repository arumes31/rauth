export function initPolicyPreview() {
    const form = document.querySelector('#policyPreviewForm');
    if (!form) return;
    const output = document.querySelector('#policyPreviewResult');
    form.addEventListener('submit', async event => {
        event.preventDefault();
        const button = form.querySelector('button');
        button.disabled = true;
        output.textContent = 'Checking policy…';
        try {
            const response = await fetch(form.action, { method: 'POST', body: new FormData(form), headers: { Accept: 'application/json' } });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || data.message || 'Policy check failed');
            const mode = data.allowed ? (data.public ? 'Public access allowed' : 'Login required') : 'Blocked by URL policy';
            output.textContent = [mode, 'Country: ' + data.country, 'Rule: ' + (data.rule || 'No public rule'),
                'Reason: ' + data.reason, ...(data.feed_id ? ['Feed: ' + data.feed_id] : [])].join(' · ');
        } catch (error) {
            output.textContent = error.message || 'Could not check policy';
        } finally {
            button.disabled = false;
        }
    });
}
