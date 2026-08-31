const form = document.querySelector('#settings');
const ruleList = document.querySelector('#rule-list');
const template = document.querySelector('#rule-template');
let config = {};

const toast = (message) => { const node = document.querySelector('#toast'); node.textContent = message; node.classList.add('show'); setTimeout(() => node.classList.remove('show'), 3200); };
const request = async (url, options = {}) => { const response = await fetch(url, options); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Anfrage fehlgeschlagen'); return data; };
const setRuleCount = () => { const count = ruleList.children.length; document.querySelector('#rule-count').textContent = `${count} ${count === 1 ? 'Regel' : 'Regeln'}`; document.querySelector('#add-first-rule').hidden = count > 0; };
const themeToggle = document.querySelector('#theme-toggle');

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('theme', theme);
  const nextTheme = theme === 'dark' ? 'Hellmodus' : 'Dunkelmodus';
  themeToggle.querySelector('span').textContent = nextTheme === 'Hellmodus' ? 'Hell' : 'Dunkel';
  themeToggle.setAttribute('aria-label', `Zum ${nextTheme} wechseln`);
  themeToggle.title = `Zum ${nextTheme} wechseln`;
}

async function withBusy(button, action) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Wird ausgeführt ...';
  try { await action(); } finally { button.disabled = false; button.textContent = label; }
}

function addRule(rule = {}) {
  const node = template.content.firstElementChild.cloneNode(true);
  node.dataset.id = rule.id || crypto.randomUUID();
  node.querySelector('.rule-name').value = rule.name || '';
  node.querySelector('.pattern').value = rule.pattern || '';
  node.querySelector('.match-type').value = rule.match_type || 'contains';
  node.querySelector('.clients').value = rule.clients || '';
  node.querySelector('.min-occurrences').value = rule.min_occurrences || 1;
  node.querySelector('.period-minutes').value = rule.period_minutes || 60;
  node.querySelector('.cooldown-minutes').value = rule.cooldown_minutes ?? 60;
  for (const input of node.querySelectorAll('.statuses input')) input.checked = (rule.statuses || ['Blocked']).includes(input.value);
  node.querySelector('.remove').addEventListener('click', () => { node.remove(); setRuleCount(); });
  ruleList.append(node);
  setRuleCount();
}

function readRules() {
  return [...ruleList.children].map(node => ({
    id: node.dataset.id, name: node.querySelector('.rule-name').value.trim(), pattern: node.querySelector('.pattern').value.trim(),
    match_type: node.querySelector('.match-type').value, statuses: [...node.querySelectorAll('.statuses input:checked')].map(input => input.value),
    clients: node.querySelector('.clients').value.trim(), min_occurrences: Number(node.querySelector('.min-occurrences').value),
    period_minutes: Number(node.querySelector('.period-minutes').value), cooldown_minutes: Number(node.querySelector('.cooldown-minutes').value)
  }));
}

function renderResults(results) {
  const list = document.querySelector('#results-list');
  document.querySelector('#active-matches').textContent = results.filter(result => result.matched).length;
  list.replaceChildren();
  if (!results.length) { const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'Keine Regeln konfiguriert.'; list.append(empty); return; }
  for (const result of results) { const node = document.createElement('article'); const name = document.createElement('span'); const count = document.createElement('strong'); const threshold = document.createElement('small'); node.className = `result${result.matched ? ' match' : ''}`; name.textContent = result.name; count.append(String(result.count), ' '); threshold.textContent = `/ ${result.threshold}`; count.append(threshold); node.append(name, count); list.append(node); }
}

async function refreshStatus() {
  const status = await request('api/status');
  document.querySelector('#last-run').textContent = status.last_run ? new Date(status.last_run).toLocaleString('de-DE') : 'Noch nie';
  document.querySelector('#result-time').textContent = status.last_run ? `Stand: ${new Date(status.last_run).toLocaleString('de-DE')}` : '';
  document.querySelector('#last-error').textContent = status.last_error || 'Keine';
  renderResults(status.last_results || []);
}

async function initialize() {
  config = await request('api/config');
  for (const [key, value] of Object.entries(config)) if (form.elements[key]) form.elements[key].value = value;
  (config.rules || []).forEach(addRule);
  await refreshStatus();
  document.querySelector('#connection').textContent = 'Bereit';
}

document.querySelector('#add-rule').addEventListener('click', () => addRule());
document.querySelector('#add-first-rule').addEventListener('click', () => addRule());
themeToggle.addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
setTheme(document.documentElement.dataset.theme || 'dark');
form.addEventListener('submit', async event => { event.preventDefault(); const data = Object.fromEntries(new FormData(form)); data.monitor_interval = Number(data.monitor_interval); data.pushover_priority = Number(data.pushover_priority); data.rules = readRules(); try { await request('api/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }); toast('Konfiguration gespeichert.'); } catch (error) { toast(error.message); } });
document.querySelector('#run-test').addEventListener('click', async event => { try { await withBusy(event.currentTarget, async () => { const data = await request('api/test', { method: 'POST' }); renderResults(data.results); await refreshStatus(); toast('Auswertung abgeschlossen.'); }); } catch (error) { toast(error.message); } });
document.querySelector('#pushover-test').addEventListener('click', async event => { try { await withBusy(event.currentTarget, async () => { await request('api/pushover-test', { method: 'POST' }); toast('Test wurde an Pushover gesendet.'); }); } catch (error) { toast(error.message); } });
initialize().catch(error => { document.querySelector('#connection').textContent = 'Nicht bereit'; toast(error.message); });