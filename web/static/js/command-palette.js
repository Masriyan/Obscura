/**
 * AEGIS Command Palette — v9.0.0
 * Global keyboard shortcut system with fuzzy search
 * Activated via Ctrl+K / ⌘K
 */
(function() {
  'use strict';

  // --- State ---
  let isOpen = false;
  let selectedIndex = 0;
  let filteredCommands = [];

  // --- Command Registry ---
  const commands = [
    // Navigation
    { id: 'nav-dashboard', label: 'Go to Dashboard', icon: 'fa-gauge-high', category: 'Navigation', action: () => window.location.href = '/' },
    { id: 'nav-new-scan', label: 'Start New Scan', icon: 'fa-crosshairs', category: 'Navigation', action: () => window.location.href = '/scan/new' },
    { id: 'nav-history', label: 'Scan History', icon: 'fa-clock-rotate-left', category: 'Navigation', action: () => window.location.href = '/scans' },
    { id: 'nav-settings', label: 'Settings & API Keys', icon: 'fa-gear', category: 'Navigation', action: () => window.location.href = '/settings' },
    { id: 'nav-queue', label: 'Scan Queue', icon: 'fa-list-check', category: 'Navigation', action: () => window.location.href = '/queue' },
    { id: 'nav-scheduled', label: 'Scheduled Scans', icon: 'fa-calendar-days', category: 'Navigation', action: () => window.location.href = '/scheduled' },

    // AI
    { id: 'ai-copilot', label: 'Open AI Copilot', icon: 'fa-brain', category: 'AI', action: () => { const t = document.getElementById('aiCopilotToggle'); if (t) t.click(); } },
    { id: 'ai-status', label: 'Check AI Status', icon: 'fa-stethoscope', category: 'AI', action: () => {
      fetch('/api/v1/ai/status').then(r => r.json()).then(d => {
        if (typeof Aegis !== 'undefined') Aegis.toast(`AI: ${d.active_provider || 'offline'} (${d.gemini?.model || 'N/A'})`, 'info', 3000);
      });
    }},

    // Actions
    { id: 'act-quick-scan', label: 'Quick Scan (Recon)', icon: 'fa-bolt', category: 'Actions', action: () => { window.location.href = '/scan/new'; } },
    { id: 'act-export-json', label: 'Export Current as JSON', icon: 'fa-code', category: 'Actions', action: () => {
      const m = window.location.pathname.match(/\/view\/(\d+)/);
      if (m) window.location.href = `/export/json?scan_id=${m[1]}`;
      else if (typeof Aegis !== 'undefined') Aegis.toast('No scan loaded', 'error');
    }},
    { id: 'act-health', label: 'Health Check', icon: 'fa-heartbeat', category: 'Actions', action: () => {
      fetch('/api/v1/health').then(r => r.json()).then(d => {
        if (typeof Aegis !== 'undefined') Aegis.toast(`v${d.version} — ${d.status}`, 'success', 3000);
      });
    }},

    // Theme (future)
    { id: 'theme-toggle', label: 'Toggle Dark/Light Mode', icon: 'fa-circle-half-stroke', category: 'Appearance', action: () => {
      document.body.classList.toggle('light-theme');
      if (typeof Aegis !== 'undefined') Aegis.toast('Theme toggled', 'info', 1500);
    }},
  ];

  // --- Create DOM ---
  const overlay = document.createElement('div');
  overlay.id = 'cmdPalette';
  overlay.innerHTML = `
    <div class="cmd-backdrop" onclick="window._closeCmdPalette()"></div>
    <div class="cmd-dialog">
      <div class="cmd-header">
        <i class="fas fa-search cmd-search-icon"></i>
        <input type="text" id="cmdInput" class="cmd-input" placeholder="Search commands..." autocomplete="off" spellcheck="false">
        <kbd class="cmd-kbd">ESC</kbd>
      </div>
      <div class="cmd-results" id="cmdResults"></div>
      <div class="cmd-footer">
        <span><kbd>↑↓</kbd> Navigate</span>
        <span><kbd>↵</kbd> Run</span>
        <span><kbd>ESC</kbd> Close</span>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  // --- Inject CSS ---
  const style = document.createElement('style');
  style.textContent = `
    #cmdPalette { display:none; position:fixed; inset:0; z-index:9999; }
    #cmdPalette.open { display:flex; align-items:flex-start; justify-content:center; padding-top:min(20vh, 160px); }
    .cmd-backdrop { position:absolute; inset:0; background:rgba(0,0,0,0.6); backdrop-filter:blur(4px); }
    .cmd-dialog {
      position:relative; width:100%; max-width:560px; background:rgba(15,15,35,0.98);
      border:1px solid rgba(99,102,241,0.2); border-radius:16px; overflow:hidden;
      box-shadow: 0 24px 80px rgba(0,0,0,0.5), 0 0 40px rgba(99,102,241,0.1);
      animation: cmdAppear 0.2s cubic-bezier(0.16,1,0.3,1);
    }
    @keyframes cmdAppear { from { opacity:0; transform:scale(0.96) translateY(-8px); } to { opacity:1; transform:scale(1) translateY(0); } }
    .cmd-header { display:flex; align-items:center; gap:0.75rem; padding:0.75rem 1rem; border-bottom:1px solid rgba(99,102,241,0.1); }
    .cmd-search-icon { color:#64748b; font-size:0.9rem; }
    .cmd-input { flex:1; background:transparent; border:none; color:#e2e8f0; font-size:0.95rem; font-family:inherit; outline:none; }
    .cmd-input::placeholder { color:#475569; }
    .cmd-kbd { font-size:0.65rem; color:#64748b; background:rgba(30,41,59,0.8); padding:0.15rem 0.4rem; border-radius:4px; border:1px solid rgba(75,85,99,0.3); font-family:'JetBrains Mono',monospace; }
    .cmd-results { max-height:360px; overflow-y:auto; padding:0.5rem; }
    .cmd-results::-webkit-scrollbar { width:4px; }
    .cmd-results::-webkit-scrollbar-thumb { background:rgba(99,102,241,0.3); border-radius:4px; }
    .cmd-category { font-size:0.65rem; font-weight:600; text-transform:uppercase; letter-spacing:0.08em; color:#475569; padding:0.5rem 0.5rem 0.25rem; }
    .cmd-item {
      display:flex; align-items:center; gap:0.75rem; padding:0.6rem 0.75rem; border-radius:8px;
      cursor:pointer; transition:background 0.1s; color:#94a3b8; font-size:0.85rem;
    }
    .cmd-item:hover, .cmd-item.selected { background:rgba(99,102,241,0.12); color:#e2e8f0; }
    .cmd-item .cmd-icon { width:28px; height:28px; border-radius:6px; background:rgba(99,102,241,0.1); display:flex; align-items:center; justify-content:center; font-size:0.8rem; color:#8b5cf6; flex-shrink:0; }
    .cmd-item.selected .cmd-icon { background:rgba(99,102,241,0.2); }
    .cmd-item .cmd-label { flex:1; }
    .cmd-item .cmd-cat { font-size:0.65rem; color:#475569; }
    .cmd-footer { display:flex; align-items:center; gap:1.5rem; padding:0.5rem 1rem; border-top:1px solid rgba(99,102,241,0.1); }
    .cmd-footer span { font-size:0.7rem; color:#475569; }
    .cmd-footer kbd { font-size:0.6rem; color:#64748b; background:rgba(30,41,59,0.8); padding:0.1rem 0.35rem; border-radius:3px; border:1px solid rgba(75,85,99,0.3); margin-right:0.2rem; font-family:'JetBrains Mono',monospace; }
    .cmd-empty { text-align:center; padding:2rem; color:#475569; font-size:0.85rem; }
  `;
  document.head.appendChild(style);

  // --- Logic ---
  const cmdInput = document.getElementById('cmdInput');
  const cmdResults = document.getElementById('cmdResults');

  function open() {
    isOpen = true;
    overlay.classList.add('open');
    cmdInput.value = '';
    selectedIndex = 0;
    render('');
    setTimeout(() => cmdInput.focus(), 50);
  }

  function close() {
    isOpen = false;
    overlay.classList.remove('open');
  }
  window._closeCmdPalette = close;

  function render(query) {
    const q = query.toLowerCase().trim();
    filteredCommands = q
      ? commands.filter(c => c.label.toLowerCase().includes(q) || c.category.toLowerCase().includes(q))
      : commands;
    
    if (!filteredCommands.length) {
      cmdResults.innerHTML = '<div class="cmd-empty"><i class="fas fa-search" style="opacity:0.3;margin-right:6px"></i>No commands found</div>';
      return;
    }

    // Group by category
    const groups = {};
    filteredCommands.forEach(c => {
      if (!groups[c.category]) groups[c.category] = [];
      groups[c.category].push(c);
    });

    let html = '';
    let idx = 0;
    for (const [cat, items] of Object.entries(groups)) {
      html += `<div class="cmd-category">${cat}</div>`;
      for (const item of items) {
        html += `
          <div class="cmd-item${idx === selectedIndex ? ' selected' : ''}" data-index="${idx}" onclick="window._runCmd(${idx})">
            <div class="cmd-icon"><i class="fas ${item.icon}"></i></div>
            <span class="cmd-label">${highlight(item.label, q)}</span>
            <span class="cmd-cat">${cat}</span>
          </div>`;
        idx++;
      }
    }
    cmdResults.innerHTML = html;
  }

  function highlight(text, q) {
    if (!q) return text;
    const idx = text.toLowerCase().indexOf(q);
    if (idx < 0) return text;
    return text.slice(0, idx) + `<strong style="color:#a78bfa">${text.slice(idx, idx + q.length)}</strong>` + text.slice(idx + q.length);
  }

  window._runCmd = function(idx) {
    const cmd = filteredCommands[idx];
    if (cmd) {
      close();
      cmd.action();
    }
  };

  // --- Keyboard ---
  document.addEventListener('keydown', (e) => {
    // Open: Ctrl+K or Meta+K
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      isOpen ? close() : open();
      return;
    }

    if (!isOpen) return;

    if (e.key === 'Escape') {
      close();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectedIndex = Math.min(selectedIndex + 1, filteredCommands.length - 1);
      render(cmdInput.value);
      cmdResults.querySelector('.cmd-item.selected')?.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectedIndex = Math.max(selectedIndex - 1, 0);
      render(cmdInput.value);
      cmdResults.querySelector('.cmd-item.selected')?.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
      e.preventDefault();
      window._runCmd(selectedIndex);
    }
  });

  if (cmdInput) {
    cmdInput.addEventListener('input', () => {
      selectedIndex = 0;
      render(cmdInput.value);
    });
  }

})();
