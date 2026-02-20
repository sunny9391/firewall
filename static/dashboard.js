'use strict';

document.addEventListener('DOMContentLoaded', () => {

  /* ── helpers ────────────────────────────────────────────────────── */
  const $ = id => document.getElementById(id);

  function setVal(id, val) {
    const el = $(id);
    if (el) el.textContent = val;
  }

  function animateNumber(el, target, duration = 600) {
    const start = parseInt(el.textContent) || 0;
    const diff  = target - start;
    const t0    = performance.now();
    if (diff === 0) return;
    function step(now) {
      const p = Math.min((now - t0) / duration, 1);
      el.textContent = Math.round(start + diff * p);
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /* ── render attack type bars ────────────────────────────────────── */
  function renderAttackTypes(attackTypes) {
    const container = $('attackTypesBar');
    if (!container) return;
    container.innerHTML = '';
    if (!attackTypes || !attackTypes.length) {
      container.innerHTML = '<p style="font-size:.78rem;color:var(--muted)">No attacks recorded yet.</p>';
      return;
    }
    const max = attackTypes[0].count;
    attackTypes.forEach(({ type, count }) => {
      const pct = max > 0 ? (count / max * 100).toFixed(1) : 0;
      container.insertAdjacentHTML('beforeend', `
        <div class="attack-bar-item">
          <div class="attack-bar-header">
            <span class="name">${type}</span>
            <span class="num">${count}</span>
          </div>
          <div class="attack-track">
            <div class="attack-fill" style="width:${pct}%"></div>
          </div>
        </div>
      `);
    });
  }

  /* ── render a simple data list ──────────────────────────────────── */
  function renderList(ulId, items, labelFn, countFn, emptyText) {
    const ul = $(ulId);
    if (!ul) return;
    ul.innerHTML = '';
    if (!items || !items.length) {
      ul.innerHTML = `<li><span class="label" style="color:var(--muted)">${emptyText}</span></li>`;
      return;
    }
    items.forEach(item => {
      const li = document.createElement('li');
      li.className = 'data-list-item';
      li.innerHTML = `<span class="label" title="${labelFn(item)}">${labelFn(item)}</span><span class="count">${countFn(item)}</span>`;
      ul.appendChild(li);
    });
  }

  /* ── render log table ───────────────────────────────────────────── */
  function renderLogs(logs) {
    const tbody = $('logTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!logs || !logs.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);padding:16px 10px">No events yet.</td></tr>';
      return;
    }
    [...logs].reverse().forEach(log => {
      const status = (log.status || '').toLowerCase();
      const cls    = status === 'malicious' ? 'badge-malicious' : status === 'valid' ? 'badge-valid' : 'badge-suspicious';
      const reason = (log.reason || 'N/A').toUpperCase();
      const reasonCls = reason === 'ML' ? 'badge-ml' : '';
      tbody.insertAdjacentHTML('beforeend', `
        <tr>
          <td>${log.timestamp || '-'}</td>
          <td class="path" title="${log.path || ''}">${log.path || '-'}</td>
          <td><span class="badge ${cls}">${log.status}</span></td>
          <td class="reason"><span class="badge ${reasonCls}">${reason}</span></td>
          <td>${log.attack_type && log.attack_type !== 'N/A' ? log.attack_type : '-'}</td>
        </tr>
      `);
    });
  }

  /* ── render health bar ──────────────────────────────────────────── */
  function renderHealth(blocked, total) {
    const pct   = total === 0 ? 0 : Math.round(blocked / total * 100);
    const fill  = $('healthFill');
    const label = $('healthLabel');
    const pctEl = $('healthPct');
    if (fill) fill.style.width = `${Math.min(pct, 100)}%`;
    if (pctEl) pctEl.textContent = `${pct}%`;
    if (label) {
      if (pct >= 40)      label.textContent = 'High threat pressure — tighten filtering and review active attack vectors.';
      else if (pct >= 15) label.textContent = 'Moderate risk — continue monitoring and tune signatures.';
      else                label.textContent = 'Threat level stable — no critical pressure detected.';
    }
  }

  /* ── main fetch ─────────────────────────────────────────────────── */
  async function fetchDashboard() {
    try {
      const res  = await fetch('/api/dashboard_data');
      const data = await res.json();

      const total   = data.totalRequests   || 0;
      const blocked = data.blockedRequests || 0;
      const ml      = data.mlAnomalies     || 0;
      const rate    = data.blockRate       || 0;

      // Animate numbers
      ['totalRequests','blockedRequests','mlAnomalies'].forEach(id => {
        const el = $(id);
        if (el) animateNumber(el, id === 'totalRequests' ? total : id === 'blockedRequests' ? blocked : ml);
      });
      setVal('blockRate', `${rate}%`);
      setVal('lastUpdated', new Date().toLocaleTimeString());

      renderHealth(blocked, total);
      renderAttackTypes(data.attackTypes || []);
      renderList('topIpsList',  data.topIps  || [], i => i.ip,  i => i.count,  'No attacker IP data yet.');
      renderList('topUrlsList', data.topUrls || [], i => i.url, i => i.count,  'No targeted URL data yet.');
      renderLogs(data.liveLogs || []);

    } catch (err) {
      console.error('Dashboard fetch error:', err);
    }
  }

  fetchDashboard();
  setInterval(fetchDashboard, 5000);
});