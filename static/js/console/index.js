// Entry point for the console pages: page scripts call initConsole() with
// their toast messages, redirect-to-section map and palette commands.
import { initConfirmForms } from './dialog.js';
import { initFilters } from './filters.js';
import { initAsyncForms } from './forms.js';
import { initPalette } from './palette.js';
import { initSections } from './sections.js';
import { initWidgets } from './widgets.js';

export { $, $$, csrfToken, setFieldValue, showModal } from './dom.js';
export { alertDialog, confirmDialog, promptDialog } from './dialog.js';
export { submitForm } from './forms.js';
export { showSection } from './sections.js';
export { toast } from './toast.js';

export function initConsole({ messages, successSection, commands } = {}) {
    initWidgets();
    initFilters();
    initConfirmForms();
    initAsyncForms();
    initSections({ messages, successSection });
    initPalette(commands);
}
