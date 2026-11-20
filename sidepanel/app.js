/**
 * PromptGuard: AI Prompt Sanitizer
 * sidepanel/app.js - Side Panel UI Controller
 * Free and unlimited open-source sanitization
 */

document.addEventListener('DOMContentLoaded', async () => {
  const sanitizer = window.PromptGuardSanitizer;
  const licensing = window.PromptGuardLicensing;

  // In-memory state
  let currentSessionMapping = {};
  let currentThreatMatches = [];
  let customRules = [];
  let enabledCategories = ['ai', 'cloud', 'vcs', 'crypto', 'database', 'auth', 'communication', 'payment', 'pii', 'generic'];

  // DOM Elements - Header & Quota
  const tierBadge = document.getElementById('tierBadge');
  const openUpgradeModalBtn = document.getElementById('openUpgradeModalBtn');
  const quotaLimitBanner = document.getElementById('quotaLimitBanner');
  const bannerUpgradeBtn = document.getElementById('bannerUpgradeBtn');

  // DOM Elements - Tabs
  const tabButtons = document.querySelectorAll('.tab-btn');
  const viewPanes = document.querySelectorAll('.view-pane');

  // DOM Elements - Sanitize Pane
  const rawInputText = document.getElementById('rawInputText');
  const sanitizeModeSelect = document.getElementById('sanitizeModeSelect');
  const sanitizeBtn = document.getElementById('sanitizeBtn');
  const sanitizeBtnLabel = document.getElementById('sanitizeBtnLabel');
  const clearInputBtn = document.getElementById('clearInputBtn');
  const grabTabBtn = document.getElementById('grabTabBtn');
  const detectedFormatBadge = document.getElementById('detectedFormatBadge');
  const threatDashboard = document.getElementById('threatDashboard');
  const threatCountTitle = document.getElementById('threatCountTitle');
  const threatPillsContainer = document.getElementById('threatPillsContainer');
  const toggleThreatDrawerBtn = document.getElementById('toggleThreatDrawerBtn');
  const threatDrawer = document.getElementById('threatDrawer');
  const outputCard = document.getElementById('outputCard');
  const sanitizedOutputText = document.getElementById('sanitizedOutputText');
  const uniqueSecretsBadge = document.getElementById('uniqueSecretsBadge');
  const copyCleanBtn = document.getElementById('copyCleanBtn');
  const sendToRestoreBtn = document.getElementById('sendToRestoreBtn');

  // DOM Elements - Restore Pane (Free & Unlimited)
  const activeMappingCountBadge = document.getElementById('activeMappingCountBadge');
  const aiResponseInputText = document.getElementById('aiResponseInputText');
  const pasteFromClipboardBtn = document.getElementById('pasteFromClipboardBtn');
  const restoreSecretsBtn = document.getElementById('restoreSecretsBtn');
  const restoredOutputCard = document.getElementById('restoredOutputCard');
  const restoredOutputText = document.getElementById('restoredOutputText');
  const restoredCountBadge = document.getElementById('restoredCountBadge');
  const copyRestoredBtn = document.getElementById('copyRestoredBtn');

  // DOM Elements - Vault Pane
  const vaultListContainer = document.getElementById('vaultListContainer');
  const shredVaultBtn = document.getElementById('shredVaultBtn');

  // DOM Elements - Rules Pane
  const categoryCheckboxes = document.querySelectorAll('.cat-checkbox');
  const customRuleName = document.getElementById('customRuleName');
  const customRulePrefix = document.getElementById('customRulePrefix');
  const customRulePattern = document.getElementById('customRulePattern');
  const addCustomRuleBtn = document.getElementById('addCustomRuleBtn');
  const customRulesList = document.getElementById('customRulesList');
  const testActivateProBtn = document.getElementById('testActivateProBtn');
  const testResetQuotaBtn = document.getElementById('testResetQuotaBtn');

  // Legacy account modal elements retained for compatibility with older layouts.
  const upgradeModal = document.getElementById('upgradeModal');
  const modalTitle = document.getElementById('modalTitle');
  const modalFreeView = document.getElementById('modalFreeView');
  const modalProView = document.getElementById('modalProView');
  const proActiveKeyDisplay = document.getElementById('proActiveKeyDisplay');
  const proMachineIdDisplay = document.getElementById('proMachineIdDisplay');
  const deactivateLicenseBtn = document.getElementById('deactivateLicenseBtn');
  const closeUpgradeModalBtn = document.getElementById('closeUpgradeModalBtn');
  const buyLifetimeBtn = document.getElementById('buyLifetimeBtn');
  const licenseKeyInput = document.getElementById('licenseKeyInput');
  const activateLicenseBtn = document.getElementById('activateLicenseBtn');
  const licenseActivationMsg = document.getElementById('licenseActivationMsg');

  // DOM Elements - Toast
  const toastNotification = document.getElementById('toastNotification');
  const toastMessage = document.getElementById('toastMessage');

  // Helper: Display floating toast feedback
  function showToast(message, duration = 2600) {
    if (!toastNotification || !toastMessage) return;
    toastMessage.textContent = message;
    toastNotification.classList.add('show');
    setTimeout(() => {
      toastNotification.classList.remove('show');
    }, duration);
  }

  // --- QUOTA & LICENSING UI UPDATE ---
  function updateQuotaDisplay() {
    if (!licensing) return;
    const state = licensing.getState();

    tierBadge.className = 'badge-tier badge-tier-pro';
    tierBadge.innerHTML = '<span>🛡️ Free &amp; Unlimited</span>';
    tierBadge.title = 'PromptGuard is free and open source.';
    if (openUpgradeModalBtn) openUpgradeModalBtn.style.display = 'none';
    if (quotaLimitBanner) quotaLimitBanner.style.display = 'none';
    sanitizeBtnLabel.textContent = 'Sanitize Prompt';
  }

  // --- TAB NAVIGATION ---
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');
      tabButtons.forEach(b => b.classList.remove('active'));
      viewPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');

      if (targetId === 'tab-vault') {
        renderVault();
      }
    });
  });

  function switchToTab(tabId) {
    const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
    if (btn) btn.click();
  }

  // --- INPUT FORMAT DETECTION ---
  rawInputText.addEventListener('input', () => {
    const text = rawInputText.value;
    if (sanitizer && sanitizer.detectInputFormat) {
      const format = sanitizer.detectInputFormat(text);
      detectedFormatBadge.textContent = `Format: ${format.toUpperCase()}`;
    }
  });

  // Keyboard Shortcut: Cmd/Ctrl + Enter to Sanitize
  rawInputText.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      runSanitization();
    }
  });

  // --- SANITIZE PIPELINE WITH QUOTA CHECK ---
  function runSanitization() {
    const rawText = rawInputText.value;
    if (!rawText.trim()) {
      showToast('⚠️ Please enter or paste some text first');
      return;
    }

    // Keep the compatibility API in sync for older stored state.
    if (licensing) {
      licensing.consumeCredit();
      updateQuotaDisplay();
    }

    const mode = sanitizeModeSelect.value;
    const options = {
      mode,
      enabledCategories,
      customRules
    };

    const result = sanitizer.sanitizeText(rawText, options);

    // Save active mapping
    currentSessionMapping = result.mapping || {};
    currentThreatMatches = result.detectedMatches || [];
    updateActiveMappingCount();

    // Render Clean Output
    sanitizedOutputText.value = result.sanitizedText;
    outputCard.style.display = 'flex';
    uniqueSecretsBadge.textContent = `${result.stats.uniqueSecrets} unique secrets masked`;

    // Render Threat Dashboard
    renderThreatDashboard(result);

    // Save to storage
    saveSessionToStorage(rawText, result);

    showToast(`✓ Sanitized ${result.stats.totalThreats} threats (free and unlimited)!`);
  }

  sanitizeBtn.addEventListener('click', runSanitization);

  // Render Threat Dashboard UI
  function renderThreatDashboard(result) {
    const totalThreats = result.stats.totalThreats;
    if (totalThreats === 0) {
      threatDashboard.style.display = 'flex';
      threatDashboard.classList.remove('has-threats');
      threatCountTitle.textContent = '🛡️ Zero Secrets Detected';
      threatCountTitle.style.color = '#34d399';
      threatPillsContainer.innerHTML = '<span class="threat-pill emerald">Clean Input - No Known Secrets</span>';
      threatDrawer.style.display = 'none';
      toggleThreatDrawerBtn.style.display = 'none';
      return;
    }

    threatDashboard.style.display = 'flex';
    threatDashboard.classList.add('has-threats');
    threatCountTitle.textContent = `⚠️ Detected ${totalThreats} Threat${totalThreats > 1 ? 's' : ''}`;
    threatCountTitle.style.color = '#fbbf24';
    toggleThreatDrawerBtn.style.display = 'block';

    threatPillsContainer.innerHTML = '';
    for (const [name, count] of Object.entries(result.threatBreakdown)) {
      const pill = document.createElement('span');
      pill.className = 'threat-pill amber';
      pill.textContent = `${count}× ${name}`;
      threatPillsContainer.appendChild(pill);
    }

    threatDrawer.innerHTML = '';
    if (result.detectedMatches && result.detectedMatches.length > 0) {
      result.detectedMatches.forEach(item => {
        const row = document.createElement('div');
        row.className = 'threat-row';
        row.innerHTML = `
          <span class="placeholder-tag">${item.placeholder}</span>
          <span class="masked-secret">${item.maskedPreview} (${item.ruleName})</span>
        `;
        threatDrawer.appendChild(row);
      });
    }
  }

  toggleThreatDrawerBtn.addEventListener('click', () => {
    if (threatDrawer.style.display === 'none') {
      threatDrawer.style.display = 'flex';
      toggleThreatDrawerBtn.textContent = 'Details ▴';
    } else {
      threatDrawer.style.display = 'none';
      toggleThreatDrawerBtn.textContent = 'Details ▾';
    }
  });

  // --- CLIPBOARD ACTIONS (FREE & UNLIMITED) ---
  copyCleanBtn.addEventListener('click', async () => {
    const text = sanitizedOutputText.value;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      showToast('✓ Clean prompt copied to clipboard!');
    } catch (err) {
      sanitizedOutputText.select();
      document.execCommand('copy');
      showToast('✓ Clean prompt copied!');
    }
  });

  clearInputBtn.addEventListener('click', () => {
    rawInputText.value = '';
    sanitizedOutputText.value = '';
    outputCard.style.display = 'none';
    threatDashboard.style.display = 'none';
    detectedFormatBadge.textContent = 'Format: Plain';
    showToast('Input cleared');
  });

  sendToRestoreBtn.addEventListener('click', () => {
    switchToTab('tab-restore');
    aiResponseInputText.focus();
  });

  // --- RESTORE PIPELINE (100% FREE & UNLIMITED) ---
  function updateActiveMappingCount() {
    const count = Object.keys(currentSessionMapping).length;
    activeMappingCountBadge.textContent = `${count} secret${count === 1 ? '' : 's'} loaded`;
  }

  pasteFromClipboardBtn.addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      aiResponseInputText.value = text;
      showToast('✓ Pasted from clipboard');
    } catch (err) {
      showToast('⚠️ Clipboard permission needed');
    }
  });

  restoreSecretsBtn.addEventListener('click', () => {
    const aiText = aiResponseInputText.value;
    if (!aiText.trim()) {
      showToast('⚠️ Paste AI generated response first');
      return;
    }

    if (Object.keys(currentSessionMapping).length === 0) {
      showToast('⚠️ No active secrets mapping loaded. Sanitize a prompt first!');
      return;
    }

    // Restoration is always free and unrestricted
    const { restoredText, restoredCount, unmappedPlaceholders } = sanitizer.restoreText(aiText, currentSessionMapping);

    restoredOutputText.value = restoredText;
    restoredOutputCard.style.display = 'flex';
    restoredCountBadge.textContent = `${restoredCount} placeholder${restoredCount === 1 ? '' : 's'} restored`;

    if (unmappedPlaceholders.length > 0) {
      showToast(`⚠️ Restored ${restoredCount} secrets. Notice: ${unmappedPlaceholders.length} unrecognized tags.`);
    } else {
      showToast(`✓ Successfully restored ${restoredCount} secrets (Free)!`);
    }
  });

  copyRestoredBtn.addEventListener('click', async () => {
    const text = restoredOutputText.value;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      showToast('✓ Restored code copied to clipboard!');
    } catch (err) {
      restoredOutputText.select();
      document.execCommand('copy');
      showToast('✓ Restored code copied!');
    }
  });

  // --- GRAB SELECTION FROM ACTIVE TAB ---
  grabTabBtn.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || tabs.length === 0) {
          showToast('⚠️ No active tab found');
          return;
        }

        const tab = tabs[0];
        if (chrome.scripting && chrome.scripting.executeScript) {
          chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => window.getSelection().toString()
          }, (results) => {
            if (results && results[0] && results[0].result) {
              rawInputText.value = results[0].result;
              detectedFormatBadge.textContent = `Format: ${sanitizer.detectInputFormat(results[0].result).toUpperCase()}`;
              showToast('✓ Grabbed selection from active page');
              runSanitization();
            } else {
              showToast('⚠️ No text was selected on the active page');
            }
          });
        } else {
          showToast('⚠️ Scripting API unavailable on this page');
        }
      });
    } else {
      showToast('⚠️ Active tab integration available in Chrome');
    }
  });

  // --- MODAL & ACCOUNT STATUS HANDLERS ---
  function openUpgradeModal() {
    if (!upgradeModal) return;
    const state = licensing ? licensing.getState() : { isPro: false };

    if (state.isPro) {
      // PRO VIEW: Shows active subscription, machine ID & multi-profile info
      modalTitle.textContent = 'Account Status: Pro Lifetime';
      modalFreeView.style.display = 'none';
      modalProView.style.display = 'flex';
      proActiveKeyDisplay.textContent = state.maskedKey || 'PG-PRO-ACTIVE';
      proMachineIdDisplay.textContent = state.machineId || 'PC-CURRENT';
    } else {
      // FREE VIEW: Shows $2 Lifetime Deal + Checkout & Key Activation
      modalTitle.textContent = 'Unlock PromptGuard Pro Lifetime';
      modalFreeView.style.display = 'flex';
      modalProView.style.display = 'none';
      licenseActivationMsg.style.display = 'none';
      if (licenseKeyInput) licenseKeyInput.value = '';
    }

    upgradeModal.classList.add('show');
  }

  function closeUpgradeModal() {
    if (upgradeModal) {
      upgradeModal.classList.remove('show');
    }
  }

  if (openUpgradeModalBtn) openUpgradeModalBtn.addEventListener('click', openUpgradeModal);
  if (bannerUpgradeBtn) bannerUpgradeBtn.addEventListener('click', openUpgradeModal);
  if (closeUpgradeModalBtn) closeUpgradeModalBtn.addEventListener('click', closeUpgradeModal);

  // Deactivate License Button (Replaces blocked window.confirm with two-click inline confirmation)
  if (deactivateLicenseBtn) {
    let confirmPending = false;
    let resetTimer = null;

    deactivateLicenseBtn.addEventListener('click', async (e) => {
      e.stopPropagation();

      if (!confirmPending) {
        confirmPending = true;
        deactivateLicenseBtn.textContent = '⚠️ Click again to confirm deactivation';
        deactivateLicenseBtn.style.color = '#ef4444';
        deactivateLicenseBtn.style.borderColor = '#ef4444';
        deactivateLicenseBtn.style.background = 'rgba(239, 68, 68, 0.15)';

        resetTimer = setTimeout(() => {
          confirmPending = false;
          deactivateLicenseBtn.textContent = 'Deactivate on this Device';
          deactivateLicenseBtn.style.color = '#fb7185';
          deactivateLicenseBtn.style.borderColor = 'rgba(244, 63, 94, 0.3)';
          deactivateLicenseBtn.style.background = 'transparent';
        }, 4000);
        return;
      }

      // Confirmed on 2nd click: execute deactivation
      clearTimeout(resetTimer);
      confirmPending = false;
      deactivateLicenseBtn.disabled = true;
      deactivateLicenseBtn.textContent = 'Deactivating...';

      try {
        await licensing.deactivateLicense();
        updateQuotaDisplay();
        closeUpgradeModal();
        showToast('✓ License deactivated on this device.');
      } catch (err) {
        console.error('Deactivation error:', err);
        showToast('⚠️ Could not deactivate license.');
      } finally {
        deactivateLicenseBtn.disabled = false;
        deactivateLicenseBtn.textContent = 'Deactivate on this Device';
        deactivateLicenseBtn.style.color = '#fb7185';
        deactivateLicenseBtn.style.borderColor = 'rgba(244, 63, 94, 0.3)';
        deactivateLicenseBtn.style.background = 'transparent';
      }
    });
  }

  // Close modal when clicking backdrop
  upgradeModal.addEventListener('click', (e) => {
    if (e.target === upgradeModal) closeUpgradeModal();
  });

  // Legacy payment controls are intentionally inert in the free open-source build.
  buyLifetimeBtn.addEventListener('click', () => {
    licenseActivationMsg.style.display = 'block';
    licenseActivationMsg.style.color = '#34d399';
    licenseActivationMsg.textContent = 'PromptGuard is free and unlimited. No license key is required.';
  });

  // Activate License Key (Handles device limit check & validation)
  activateLicenseBtn.addEventListener('click', async () => {
    const key = licenseKeyInput.value.trim();
    if (!key) {
      licenseActivationMsg.style.display = 'block';
      licenseActivationMsg.style.color = '#fb7185';
      licenseActivationMsg.textContent = 'Please enter a license key.';
      return;
    }

    activateLicenseBtn.disabled = true;
    activateLicenseBtn.textContent = 'Verifying...';
    licenseActivationMsg.style.display = 'block';
    licenseActivationMsg.style.color = '#94a3b8';
    licenseActivationMsg.textContent = 'Verifying key & checking device limit (max 2 devices)...';

    const res = await licensing.activateLicenseKey(key);

    activateLicenseBtn.disabled = false;
    activateLicenseBtn.textContent = 'Activate';

    if (res.success) {
      licenseActivationMsg.style.color = '#34d399';
      licenseActivationMsg.textContent = res.message;
      updateQuotaDisplay();
      setTimeout(() => {
        closeUpgradeModal();
        showToast('✓ PromptGuard is already free and unlimited!');
      }, 1000);
    } else {
      licenseActivationMsg.style.color = '#fb7185';
      licenseActivationMsg.textContent = res.message;
    }
  });

  // Developer Testing Controls
  if (testActivateProBtn) {
    testActivateProBtn.addEventListener('click', () => {
      licensing.activateLicenseKey('PROGUARD2026');
      updateQuotaDisplay();
      showToast('⭐ Test Pro Activated (Unlimited)!');
    });
  }

  if (testResetQuotaBtn) {
    testResetQuotaBtn.addEventListener('click', () => {
      licensing.revokeLicense();
      updateQuotaDisplay();
      showToast('🔄 Free and unlimited access restored');
    });
  }

  // --- STORAGE & VAULT MANAGEMENT ---
  function saveSessionToStorage(rawInput, result) {
    if (typeof chrome === 'undefined' || !chrome.storage) return;

    if (chrome.storage.session) {
      chrome.storage.session.set({
        activePromptGuardMapping: result.mapping
      }).catch(err => console.warn('Storage session error:', err));
    }

    if (chrome.storage.local) {
      chrome.storage.local.get(['promptGuardVaultHistory'], (data) => {
        const history = data.promptGuardVaultHistory || [];
        const sessionRecord = {
          id: 'sess_' + Date.now(),
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          date: new Date().toLocaleDateString(),
          threatCount: result.stats.totalThreats,
          uniqueCount: result.stats.uniqueSecrets,
          previewSnippet: rawInput.slice(0, 60).replace(/\s+/g, ' ') + (rawInput.length > 60 ? '...' : ''),
          mapping: result.mapping
        };

        history.unshift(sessionRecord);
        if (history.length > 15) history.pop();

        chrome.storage.local.set({ promptGuardVaultHistory: history });
      });
    }
  }

  function renderVault() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      vaultListContainer.innerHTML = '<div style="font-size: 11px; color: var(--text-muted); text-align: center; padding: 20px;">Vault requires Chrome storage permissions.</div>';
      return;
    }

    chrome.storage.local.get(['promptGuardVaultHistory'], (data) => {
      const history = data.promptGuardVaultHistory || [];
      if (history.length === 0) {
        vaultListContainer.innerHTML = '<div style="font-size: 11px; color: var(--text-muted); text-align: center; padding: 20px;">No previous sessions in this vault.</div>';
        return;
      }

      vaultListContainer.innerHTML = '';
      history.forEach((sess) => {
        const item = document.createElement('div');
        item.className = 'history-item';
        item.innerHTML = `
          <div style="display: flex; flex-direction: column; gap: 3px; max-width: 70%;">
            <div style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 11px; font-weight: 700; color: #f1f5f9;">${sess.timestamp}</span>
              <span class="threat-pill amber" style="font-size: 9px; padding: 1px 5px;">${sess.threatCount} Threats</span>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${escapeHtml(sess.previewSnippet)}
            </div>
          </div>
          <button class="btn btn-secondary btn-sm load-session-btn" data-id="${sess.id}">
            Load Mapping
          </button>
        `;

        item.querySelector('.load-session-btn').addEventListener('click', () => {
          currentSessionMapping = sess.mapping || {};
          updateActiveMappingCount();
          switchToTab('tab-restore');
          showToast(`✓ Loaded mapping from ${sess.timestamp} (${Object.keys(currentSessionMapping).length} secrets)`);
        });

        vaultListContainer.appendChild(item);
      });
    });
  }

  shredVaultBtn.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.remove(['promptGuardVaultHistory'], () => {
        currentSessionMapping = {};
        updateActiveMappingCount();
        renderVault();
        showToast('💣 Vault & mappings completely shredded');
      });
    }
  });

  // --- RULES & SETTINGS ---
  async function loadSettings() {
    if (licensing) {
      await licensing.loadState();
      updateQuotaDisplay();
    }

    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;

    chrome.storage.local.get(['enabledCategories', 'customRules', 'promptGuardActiveMapping'], (data) => {
      if (data.enabledCategories) {
        enabledCategories = data.enabledCategories;
        categoryCheckboxes.forEach(cb => {
          cb.checked = enabledCategories.includes(cb.value);
        });
      }

      if (data.customRules) {
        customRules = data.customRules;
        renderCustomRulesList();
      }

      if (chrome.storage.session) {
        chrome.storage.session.get(['activePromptGuardMapping'], (sData) => {
          if (sData && sData.activePromptGuardMapping) {
            currentSessionMapping = sData.activePromptGuardMapping;
            updateActiveMappingCount();
          }
        });
      }
    });
  }

  categoryCheckboxes.forEach(cb => {
    cb.addEventListener('change', () => {
      enabledCategories = Array.from(categoryCheckboxes)
        .filter(c => c.checked)
        .map(c => c.value);

      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ enabledCategories });
      }
      showToast('Filters updated');
    });
  });

  addCustomRuleBtn.addEventListener('click', () => {
    const name = customRuleName.value.trim();
    const prefix = customRulePrefix.value.trim();
    const pattern = customRulePattern.value.trim();

    if (!name || !pattern) {
      showToast('⚠️ Please enter rule name and regex pattern');
      return;
    }

    try {
      new RegExp(pattern);
    } catch (e) {
      showToast('⚠️ Invalid regular expression');
      return;
    }

    const ruleObj = {
      id: 'cr_' + Date.now(),
      name,
      prefix: prefix || 'CUSTOM_SECRET',
      pattern,
      flags: 'g'
    };

    customRules.push(ruleObj);
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ customRules });
    }

    customRuleName.value = '';
    customRulePrefix.value = '';
    customRulePattern.value = '';
    renderCustomRulesList();
    showToast(`✓ Added custom rule: ${name}`);
  });

  function renderCustomRulesList() {
    customRulesList.innerHTML = '';
    if (customRules.length === 0) return;

    customRules.forEach((rule, idx) => {
      const item = document.createElement('div');
      item.className = 'history-item';
      item.style.padding = '6px 10px';
      item.innerHTML = `
        <div>
          <strong style="color: #f1f5f9; font-size: 11px;">${escapeHtml(rule.name)}</strong>
          <div style="font-size: 10px; color: var(--text-muted); font-family: monospace;">/${escapeHtml(rule.pattern)}/g [${escapeHtml(rule.prefix)}]</div>
        </div>
        <button class="btn btn-danger btn-sm del-rule-btn" data-index="${idx}">Delete</button>
      `;

      item.querySelector('.del-rule-btn').addEventListener('click', () => {
        customRules.splice(idx, 1);
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ customRules });
        }
        renderCustomRulesList();
        showToast('Rule deleted');
      });

      customRulesList.appendChild(item);
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;');
  }

  await loadSettings();
});
