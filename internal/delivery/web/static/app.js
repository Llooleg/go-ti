'use strict';

const form = document.getElementById('lookup-form');
const input = document.getElementById('target');
const button = document.getElementById('analyze-btn');
const statusBox = document.getElementById('status');
const reportBox = document.getElementById('report');

form.addEventListener('submit', (event) => {
  event.preventDefault();
  analyze();
});

async function analyze() {
  const target = input.value.trim();
  if (!target) {
    showStatus('Please enter a link or a file path.', 'error');
    return;
  }

  setLoading(true);
  hideStatus();
  reportBox.hidden = true;

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: target }),
    });
    const data = await response.json();
    render(data);
  } catch (err) {
    showStatus('Request failed: ' + err.message, 'error');
  } finally {
    setLoading(false);
  }
}

function render(data) {
  if (data.error) {
    showStatus(data.error, 'error');
    return;
  }
  if (data.warning) {
    showStatus(data.warning, 'warning');
  }
  if (!data.result) {
    if (!data.warning) showStatus('Empty response from server.', 'error');
    return;
  }
  renderReport(data.result);
}

function renderReport(r) {
  reportBox.replaceChildren();

  reportBox.append(el('h2', {}, r.kind === 'link' ? 'Link analysis' : 'File analysis'));

  const meta = el('div', { class: 'meta' });
  meta.append(fieldSpan(r.kind === 'link' ? 'URL' : 'Path', r.input));
  if (r.kind === 'link' && r.resolvedIp) {
    meta.append(fieldSpan('Resolved IPv4', r.resolvedIp));
  }
  reportBox.append(meta);

  reportBox.append(statsCard(r.stats));
  if (r.abuse) {
    reportBox.append(abuseCard(r.abuse));
  }

  reportBox.hidden = false;
}

function statsCard(stats) {
  const card = el('section', { class: 'card' });
  card.append(el('h3', {}, 'VirusTotal verdicts — ' + totalEngines(stats) + ' engines'));

  const tiles = el('div', { class: 'tiles' });
  tiles.append(tile('malicious', stats.malicious, 'bad'));
  tiles.append(tile('suspicious', stats.suspicious, 'warn'));
  tiles.append(tile('harmless', stats.harmless, 'good'));
  tiles.append(tile('undetected', stats.undetected, 'meh'));
  tiles.append(tile('timeout', stats.timeout, 'meh'));
  for (const [key, value] of Object.entries(stats.other || {})) {
    tiles.append(tile(key, value, 'meh'));
  }
  card.append(tiles);
  return card;
}

function abuseCard(a) {
  const card = el('section', { class: 'card' });
  card.append(el('h3', {}, 'AbuseIPDB — ' + a.ipAddress));

  const bar = el('div', { class: 'bar' });
  const confidence = Math.max(0, Math.min(a.abuseConfidenceScore, 100));
  bar.append(el('div', {
    class: 'bar-fill ' + (confidence < 10 ? 'low' : confidence < 50 ? 'mid' : 'high'),
    style: 'width:' + confidence + '%',
  }));
  card.append(bar);
  card.append(el('p', { class: 'bar-label' }, 'abuse confidence ' + a.abuseConfidenceScore + '%'));

  const dl = el('dl', { class: 'fields' });
  const rows = [
    ['country', a.countryCode || 'unknown'],
    ['ISP', a.isp || 'unknown'],
    ['usage type', a.usageType || 'unknown'],
    ['domain', a.domain || 'unknown'],
    ['hostnames', (a.hostnames || []).join(', ') || 'none'],
    ['total reports', String(a.totalReports)],
    ['distinct reporters', String(a.numDistinctUsers)],
    ['last reported at', a.lastReportedAt || 'never'],
    ['whitelisted', a.isWhitelisted ? 'yes' : 'no'],
    ['public', a.isPublic ? 'yes (IPv' + a.ipVersion + ')' : 'no'],
  ];
  for (const [term, def] of rows) {
    dl.append(el('dt', {}, term), el('dd', {}, def));
  }
  card.append(dl);
  return card;
}

function totalEngines(stats) {
  let total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected + stats.timeout;
  for (const value of Object.values(stats.other || {})) total += value;
  return total;
}

function tile(label, value, tone) {
  const t = el('div', { class: 'tile ' + tone });
  t.append(el('span', { class: 'num' }, String(value)));
  t.append(el('span', { class: 'label' }, label));
  return t;
}

function fieldSpan(label, value) {
  const span = el('span', {});
  span.append(el('strong', {}, label + ': '), document.createTextNode(value));
  return span;
}

function showStatus(message, tone) {
  statusBox.textContent = message;
  statusBox.className = 'status ' + tone;
  statusBox.hidden = false;
}

function hideStatus() {
  statusBox.hidden = true;
}

function setLoading(loading) {
  button.disabled = loading;
  button.textContent = loading ? 'Analyzing…' : 'Analyze';
}

// el builds an element with attributes and text content.
// All dynamic values go through textContent, never innerHTML.
function el(tag, attrs, text) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === 'class' || key === 'style') {
      node.setAttribute(key, value);
    } else {
      node[key] = value;
    }
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}
