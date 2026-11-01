// Country restrictions use the same control in the add and edit forms.
export function initPolicyForms() {
    document.querySelectorAll('[data-policy-fields]').forEach(fields => {
        const mode = fields.querySelector('[name="country_mode"]');
        const selection = fields.querySelector('[data-country-selection]');
        const count = fields.querySelector('[data-country-count]');
        const search = fields.querySelector('[data-country-search]');
        const countries = [...fields.querySelectorAll('[name="allowed_countries"]')];
        const sync = () => {
            const restricted = mode.value === 'selected';
            selection.hidden = !restricted;
            selection.querySelectorAll('input').forEach(input => { input.disabled = !restricted; });
            count.textContent = countries.filter(input => input.checked).length + ' selected';
        };
        const access = fields.form?.querySelector('[name="action"]');
        const defaultFeed = fields.querySelector('[data-default-feed]');
        access?.addEventListener('change', () => {
            if (defaultFeed) defaultFeed.checked = access.value === 'allow';
        });
        mode.addEventListener('change', sync);
        fields.addEventListener('change', sync);
        search.addEventListener('input', () => {
            const query = search.value.trim().toLocaleLowerCase();
            fields.querySelectorAll('[data-country-option]').forEach(label => {
                label.hidden = !label.textContent.toLocaleLowerCase().includes(query);
            });
        });
        fields.form?.addEventListener('submit', event => {
            if (mode.value === 'selected' && !countries.some(input => input.checked)) {
                event.preventDefault();
                search.setCustomValidity('Select at least one allowed country.');
                search.reportValidity();
            }
        });
        fields.addEventListener('change', () => search.setCustomValidity(''));
        sync();
    });
}
