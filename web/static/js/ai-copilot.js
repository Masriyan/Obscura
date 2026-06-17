/**
 * AEGIS AI Copilot — v9.0.0
 * Interactive AI chat panel with scan context awareness
 */
(function() {
  'use strict';

  // --- DOM Elements ---
  const panel = document.getElementById('aiCopilotPanel');
  const toggle = document.getElementById('aiCopilotToggle');
  const messages = document.getElementById('aiChatMessages');
  const input = document.getElementById('aiChatInput');
  const sendBtn = document.getElementById('aiSendBtn');
  const quickActions = document.getElementById('aiQuickActions');
  const providerBadge = document.getElementById('aiProviderBadge');

  if (!panel || !toggle) return;

  // --- State ---
  let conversationId = null;
  let isOpen = false;
  let isSending = false;
  let currentScanId = null;

  // Try to detect scan_id from the page URL (e.g. /view/123)
  const scanIdMatch = window.location.pathname.match(/\/view\/(\d+)/);
  if (scanIdMatch) {
    currentScanId = parseInt(scanIdMatch[1]);
  }

  // --- Panel Toggle ---
  toggle.addEventListener('click', () => {
    isOpen = !isOpen;
    panel.classList.toggle('open', isOpen);
    toggle.classList.toggle('active', isOpen);
    toggle.querySelector('i').className = isOpen ? 'fas fa-times' : 'fas fa-brain';
    if (isOpen && input) input.focus();
  });

  // Close on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isOpen) {
      isOpen = false;
      panel.classList.remove('open');
      toggle.classList.remove('active');
      toggle.querySelector('i').className = 'fas fa-brain';
    }
  });

  // --- Send Message ---
  async function sendMessage(text) {
    if (!text.trim() || isSending) return;
    isSending = true;
    sendBtn.disabled = true;

    // Add user message
    appendMessage('user', text);
    input.value = '';
    autoResizeTextarea();

    // Show typing indicator
    const typingEl = showTyping();

    try {
      const payload = {
        message: text,
        conversation_id: conversationId,
      };
      if (currentScanId) {
        payload.scan_id = currentScanId;
      }

      const response = await fetch('/api/v1/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      // Remove typing indicator
      if (typingEl && typingEl.parentNode) {
        typingEl.parentNode.removeChild(typingEl);
      }

      if (data.error) {
        appendMessage('assistant', '⚠️ ' + data.error);
      } else {
        conversationId = data.conversation_id;
        appendMessage('assistant', data.response);
        updateProviderBadge(data.provider);
      }
    } catch (err) {
      if (typingEl && typingEl.parentNode) {
        typingEl.parentNode.removeChild(typingEl);
      }
      appendMessage('assistant', '⚠️ Connection error. Please check that the server is running.');
    }

    isSending = false;
    sendBtn.disabled = false;
  }

  // --- UI Helpers ---
  function appendMessage(role, content) {
    const div = document.createElement('div');
    div.className = `ai-message ${role}`;
    // Simple markdown rendering for assistant messages
    if (role === 'assistant') {
      div.innerHTML = renderMarkdown(content);
    } else {
      div.textContent = content;
    }
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
  }

  function showTyping() {
    const div = document.createElement('div');
    div.className = 'ai-typing';
    div.innerHTML = `
      <div class="ai-typing-dots">
        <span></span><span></span><span></span>
      </div>
      <span>Analyzing...</span>
    `;
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
    return div;
  }

  function updateProviderBadge(provider) {
    if (!providerBadge) return;
    const names = {
      'gemini': 'Gemini',
      'openai': 'GPT-4',
      'anthropic': 'Claude',
      'fallback': 'Offline',
      'rule-based': 'Offline',
    };
    providerBadge.className = `ai-provider-badge ${provider || 'fallback'}`;
    providerBadge.textContent = names[provider] || provider || 'Offline';
  }

  function renderMarkdown(text) {
    if (!text) return '';
    // Escape all HTML special chars before processing markdown
    let html = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');

    // Code blocks
    html = html.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
      return `<pre><code>${code.trim()}</code></pre>`;
    });

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

    // Italic
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

    // Headers (## and ###)
    html = html.replace(/^### (.+)$/gm, '<strong style="color:var(--text-heading);font-size:0.85rem">$1</strong>');
    html = html.replace(/^## (.+)$/gm, '<strong style="color:var(--text-heading);font-size:0.9rem">$1</strong>');

    // Lists
    html = html.replace(/^- (.+)$/gm, '• $1');
    html = html.replace(/^\d+\. (.+)$/gm, (_, text) => `▸ ${text}`);

    // Line breaks
    html = html.replace(/\n/g, '<br>');

    return html;
  }

  // --- Auto-resize textarea ---
  function autoResizeTextarea() {
    if (!input) return;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 120) + 'px';
  }

  // --- Event Listeners ---
  if (sendBtn) {
    sendBtn.addEventListener('click', () => sendMessage(input.value));
  }

  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage(input.value);
      }
    });
    input.addEventListener('input', autoResizeTextarea);
  }

  // Quick actions
  if (quickActions) {
    quickActions.addEventListener('click', (e) => {
      const btn = e.target.closest('.ai-quick-action');
      if (btn) {
        const prompt = btn.dataset.prompt;
        if (prompt) sendMessage(prompt);
      }
    });
  }

  // --- Initialize: fetch AI status ---
  fetch('/api/v1/ai/status')
    .then(r => r.json())
    .then(data => {
      updateProviderBadge(data.active_provider);
      // Update subtitle
      const subtitle = panel.querySelector('.ai-subtitle');
      if (subtitle && data.active_provider) {
        const models = {
          gemini: data.gemini?.model || 'gemini-2.5-flash',
          openai: data.openai?.model || 'gpt-4',
          anthropic: data.anthropic?.model || 'claude-3',
        };
        subtitle.textContent = `Powered by ${models[data.active_provider] || data.active_provider}`;
      }
    })
    .catch(() => {
      updateProviderBadge('fallback');
    });

})();
