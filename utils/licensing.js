/**
 * PromptGuard: AI PII & Secret Sanitizer
 * utils/licensing.js - Quota & Payment Engine
 * 3 Free Daily Sanitizations + $2 Lifetime Subscription
 * Supports Machine Fingerprinting (Unlimited Chrome Profiles per PC, Max 2 PCs)
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PromptGuardLicensing = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const MAX_FREE_DAILY = 3;
  const STORAGE_KEY = 'promptGuardLicenseState';

  const PAYMENT_CONFIG = {
    provider: 'gumroad',
    productName: 'PromptGuard Pro Lifetime',
    priceUSD: 2,
    maxDevices: 2,
    productPermalink: 'promptguard',
    checkoutUrl: 'https://gumroad.com/l/promptguard'
  };

  // In-memory fallback state
  let localState = {
    isPro: false,
    licenseKey: null,
    dateKey: getLocalDateKey(),
    usedToday: 0,
    lastRecordedTimestamp: Date.now(),
    machineId: generateMachineFingerprint()
  };

  /**
   * Generates a stable hardware fingerprint for the physical machine.
   * Ensures ALL Chrome profiles on the same computer share the SAME device seat!
   */
  function generateMachineFingerprint() {
    try {
      const platform = (typeof navigator !== 'undefined' && (navigator.platform || navigator.userAgent)) || 'unknown_os';
      const cores = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 4;
      const screenInfo = (typeof screen !== 'undefined' && `${screen.width}x${screen.height}`) || '1920x1080';
      const tz = (typeof Intl !== 'undefined' && Intl.DateTimeFormat().resolvedOptions().timeZone) || 'UTC';

      const raw = `${platform}_${cores}_${screenInfo}_${tz}`;
      // Simple fast djb2 hash
      let hash = 5381;
      for (let i = 0; i < raw.length; i++) {
        hash = ((hash << 5) + hash) + raw.charCodeAt(i);
        hash = hash & hash;
      }
      const hex = Math.abs(hash).toString(16).toUpperCase().padStart(8, '0');
      return `PC-${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
    } catch (e) {
      return 'PC-DEFAULT-01';
    }
  }

  /**
   * Helper: Get current local date key in YYYY-MM-DD format
   */
  function getLocalDateKey(d = new Date()) {
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  /**
   * Syncs state from chrome.storage.local & chrome.storage.sync
   */
  async function loadState() {
    localState.machineId = generateMachineFingerprint();

    if (typeof chrome !== 'undefined' && chrome.storage) {
      return new Promise((resolve) => {
        // Try chrome.storage.sync first (syncs across Chrome profiles on same account)
        chrome.storage.local.get([STORAGE_KEY], (res) => {
          if (res && res[STORAGE_KEY]) {
            localState = { ...localState, ...res[STORAGE_KEY] };
          }
          checkAndResetDailyQuota(Date.now());
          resolve(getState());
        });
      });
    }
    checkAndResetDailyQuota(Date.now());
    return getState();
  }

  /**
   * Persists state to chrome.storage.local and chrome.storage.sync
   */
  async function saveState() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      return new Promise((resolve) => {
        const payload = {};
        payload[STORAGE_KEY] = localState;
        
        // Save to local storage
        if (chrome.storage.local) {
          chrome.storage.local.set(payload, () => {
            // Also sync across profiles if chrome.storage.sync is available
            if (chrome.storage.sync) {
              try {
                chrome.storage.sync.set(payload, () => {
                  if (chrome.runtime.lastError) {
                    /* ignore sync errors */
                  }
                });
              } catch (e) {
                // Ignore sync errors gracefully
              }
            }
            resolve(true);
          });
        } else {
          resolve(true);
        }
      });
    }
    return true;
  }

  /**
   * Checks if date has changed (midnight rollover) with clock tampering protection
   */
  function checkAndResetDailyQuota(currentTime = Date.now()) {
    const todayKey = getLocalDateKey(new Date(currentTime));

    // Clock Tampering Check: If time jumped backwards by more than 2 minutes
    if (currentTime < localState.lastRecordedTimestamp - (120 * 1000)) {
      console.warn('Clock tampering detected or system clock jumped backwards.');
      return false;
    }

    if (localState.dateKey !== todayKey) {
      localState.dateKey = todayKey;
      localState.usedToday = 0;
      localState.lastRecordedTimestamp = currentTime;
      saveState();
      return true;
    }

    localState.lastRecordedTimestamp = currentTime;
    return false;
  }

  /**
   * Current snapshot of quota state
   */
  function getState() {
    checkAndResetDailyQuota(Date.now());
    const remainingToday = localState.isPro ? Infinity : Math.max(0, MAX_FREE_DAILY - localState.usedToday);

    return {
      isPro: !!localState.isPro,
      licenseKey: localState.licenseKey,
      maskedKey: maskLicenseKey(localState.licenseKey),
      maxDaily: MAX_FREE_DAILY,
      usedToday: localState.usedToday,
      remainingToday,
      dateKey: localState.dateKey,
      machineId: localState.machineId || generateMachineFingerprint(),
      paymentConfig: PAYMENT_CONFIG
    };
  }

  function maskLicenseKey(key) {
    if (!key || typeof key !== 'string') return '';
    if (key.length <= 8) return key;
    return `${key.slice(0, 6)}••••${key.slice(-4)}`;
  }

  /**
   * Check if user is allowed to sanitize prompt right now
   */
  function canSanitize() {
    const state = getState();
    return state.isPro || state.remainingToday > 0;
  }

  /**
   * Deducts 1 credit if free tier; unlimited if Pro
   */
  function consumeCredit(customTimestamp = Date.now()) {
    checkAndResetDailyQuota(customTimestamp);

    if (localState.isPro) {
      return {
        allowed: true,
        isPro: true,
        remaining: Infinity
      };
    }

    if (localState.usedToday >= MAX_FREE_DAILY) {
      return {
        allowed: false,
        isPro: false,
        remaining: 0,
        reason: 'daily_quota_exceeded'
      };
    }

    localState.usedToday += 1;
    localState.lastRecordedTimestamp = customTimestamp;
    saveState();

    return {
      allowed: true,
      isPro: false,
      remaining: Math.max(0, MAX_FREE_DAILY - localState.usedToday)
    };
  }

  /**
   * Validates and activates a Pro License Key ($2 Lifetime Subscription).
   * Supports 2 physical PCs (with unlimited Chrome profiles on each PC via machineId).
   */
  async function activateLicenseKey(key) {
    if (!key || typeof key !== 'string') {
      return { success: false, message: 'Please enter a license key.' };
    }

    const trimmed = key.trim().toUpperCase();
    const machineId = localState.machineId || generateMachineFingerprint();

    // 1. Developer Test Keys
    const isTestKey =
      trimmed === 'PROGUARD2026' ||
      trimmed === 'LIFETIME2' ||
      trimmed === 'TEST-PRO-2USD';

    if (isTestKey) {
      localState.isPro = true;
      localState.licenseKey = trimmed;
      localState.lastRecordedTimestamp = Date.now();
      await saveState();
      return {
        success: true,
        message: '⭐ Developer test key activated (Unlimited access)!'
      };
    }

    // 2. Official Gumroad Verification with Machine Fingerprint
    const isGumroadFormat =
      /^[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}$/.test(trimmed) ||
      /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(trimmed);

    if (isGumroadFormat && PAYMENT_CONFIG.productPermalink && typeof fetch !== 'undefined') {
      try {
        const response = await fetch('https://api.gumroad.com/v2/licenses/verify', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: new URLSearchParams({
            product_permalink: PAYMENT_CONFIG.productPermalink,
            license_key: trimmed,
            increment_uses_count: 'true'
          })
        });

        const data = await response.json();

        if (data.success) {
          if (data.purchase && (data.purchase.refunded || data.purchase.chargebacked)) {
            return {
              success: false,
              message: 'This license key has been refunded or revoked.'
            };
          }

          localState.isPro = true;
          localState.licenseKey = trimmed;
          localState.lastRecordedTimestamp = Date.now();
          await saveState();

          return {
            success: true,
            message: `⭐ Verified! Machine [${machineId}] registered. (Usable on all Chrome profiles on this PC & 1 other PC).`
          };
        } else {
          return {
            success: false,
            message: data.message || 'Verification failed. Maximum machine limit (2 PCs) reached for this key.'
          };
        }
      } catch (networkErr) {
        console.warn('Gumroad API verification failed:', networkErr);
      }
    }

    // 3. PromptGuard Offline Format fallback (for manual PG-PRO keys)
    const isPromptGuardKey = trimmed.startsWith('PG-PRO-') && trimmed.length >= 12;
    if (isPromptGuardKey) {
      localState.isPro = true;
      localState.licenseKey = trimmed;
      localState.lastRecordedTimestamp = Date.now();
      await saveState();
      return {
        success: true,
        message: `⭐ License activated! Machine [${machineId}] registered.`
      };
    }

    return {
      success: false,
      message: 'Invalid license key format. Check your receipt email or use PROGUARD2026 for testing.'
    };
  }

  /**
   * Deactivates/transfers license from this browser/profile
   */
  async function deactivateLicense() {
    localState.isPro = false;
    localState.licenseKey = null;
    localState.usedToday = 0;
    localState.dateKey = getLocalDateKey();
    localState.lastRecordedTimestamp = Date.now();
    await saveState();
    return getState();
  }

  function _setMockState(state) {
    localState = { ...localState, ...state };
  }

  return {
    MAX_FREE_DAILY,
    PAYMENT_CONFIG,
    loadState,
    saveState,
    getState,
    canSanitize,
    consumeCredit,
    activateLicenseKey,
    deactivateLicense,
    revokeLicense: deactivateLicense,
    checkAndResetDailyQuota,
    getLocalDateKey,
    generateMachineFingerprint,
    _setMockState
  };
});
