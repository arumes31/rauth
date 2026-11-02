export const actionColors = { authenticated:'#22c55e', bypass:'#38bdf8', blocked:'#ef4444', login_required:'#eab308', rate_limited:'#fb923c', error:'#c084fc' };
export const actionLabels = { authenticated:'Authenticated', bypass:'Public access', blocked:'Blocked', login_required:'Login required', rate_limited:'Rate limited', error:'Error' };
export function finite(value) { return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null; }
export function formatNumber(value) { return finite(value) === null ? '—' : new Intl.NumberFormat(undefined,{maximumFractionDigits:1}).format(value); }
export function milliseconds(value) { return finite(value) === null ? '—' : `${formatNumber(value)} ms`; }
export function bytes(value) { if(finite(value)===null)return '—';const units=['B','KiB','MiB','GiB'];let index=0;while(value>=1024&&index<3){value/=1024;index++;}return `${formatNumber(value)} ${units[index]}`; }
export function summary(data) { const counts={};for(const row of data.actions||[])counts[row.key]=finite(row.count)||0;return {Total:data.total,Allowed:(counts.authenticated||0)+(counts.bypass||0),Blocked:counts.blocked||0,Login:counts.login_required||0,Errors:(counts.error||0)+(counts.rate_limited||0)}; }
export function metricValues(snapshot) { const values={};for(const point of snapshot?.points||[]){if(finite(point.value)!==null)values[point.name]=point.value;}return values; }
export function nodeLabel(node) { return node.node_name || node.node_id || 'Unknown node'; }
export function chartPosition(at,start,end,width) { const value=Date.parse(at),lo=Date.parse(start),hi=Date.parse(end);return Number.isFinite(value)&&hi>lo?Math.max(0,Math.min(width,(value-lo)/(hi-lo)*width)):null; }
