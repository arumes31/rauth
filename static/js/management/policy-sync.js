// Only server-computed confirmations determine the summary; text is never HTML.
export function initPolicySync() {
 const panel = document.querySelector('[data-policy-sync]');
 if (!panel) return;
 const summary = panel.querySelector('[data-policy-summary]');
 const source = panel.querySelector('[data-policy-source]');
 const published = panel.querySelector('[data-policy-published]');
 const confirmed = panel.querySelector('[data-policy-confirmed]');
 const rows = panel.querySelector('[data-policy-nodes]');
 let loading = false;
 const cell = (row, value) => { const td = document.createElement('td'); td.textContent = String(value); row.append(td); return td; };
 function unavailable() {
  summary.textContent = 'Unable to read node confirmations.';
  source.textContent = published.textContent = confirmed.textContent = '—';
  rows.replaceChildren(); const row = document.createElement('tr'); const td = cell(row, 'Confirmations unavailable.'); td.colSpan = 5; rows.append(row);
 }
 async function refresh() {
  if (loading || document.hidden) return;
  loading = true;
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 6000);
  try {
   const response = await fetch('/rauthmgmt/policy-status', { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal, headers: { Accept: 'application/json' } });
   if (!response.ok) throw new Error('unavailable');
   const data = await response.json(); if (!Array.isArray(data.nodes) || data.nodes.length > 64) throw new Error('invalid status');
   source.textContent = String(data.source_revision);
   published.textContent = data.desired.revision > 0 ? `v${data.desired.revision}` : 'Awaiting publication';
   confirmed.textContent = `${data.confirmed} of ${data.nodes.length}`;
   summary.textContent = data.all_confirmed ? 'All assigned nodes confirmed this policy.' : (!data.source.available ? 'Publication is unavailable. The last confirmations are shown below.' : (!data.source.current ? 'Saved source is awaiting publication.' : 'Waiting for node confirmations.'));
   rows.replaceChildren();
   for (const node of data.nodes) {
    const row = document.createElement('tr');
    const identity = cell(row, node.node_id); identity.className = 'text-break';
    const role = document.createElement('small'); role.className = 'd-block text-muted'; role.textContent = node.role || 'Unassigned'; identity.append(role);
    cell(row, node.report.applied.revision ? `v${node.report.applied.revision}` : '—');
    cell(row, node.report.desired.revision ? `v${node.report.desired.revision}` : '—');
    cell(row, node.recent ? new Date(node.received_at).toLocaleTimeString() : 'No recent report');
    const state = cell(row, ''); const chip = document.createElement('span');
    chip.className = node.confirmed ? 'chip ok' : 'chip warn';
    chip.textContent = node.confirmed ? 'Confirmed' : (!node.eligible ? 'No eligible confirmation' : (!node.recent ? 'Awaiting report' : 'Pending'));
    state.append(chip); rows.append(row);
   }
  } catch (_) { unavailable(); }
  finally { clearTimeout(timer); loading = false; }
 }
 panel.querySelector('[data-policy-refresh]').addEventListener('click', refresh);
 document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
 refresh(); setInterval(refresh, 2000);
}
