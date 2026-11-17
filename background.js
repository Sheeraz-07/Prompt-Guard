/**
 * PromptGuard: AI PII & Secret Sanitizer
 * background.js - Service Worker (Manifest V3)
 * Configures Side Panel behavior and manages lifecycle.
 */

// Enable side panel to open on extension action icon click
chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel
    .setPanelBehavior({ openPanelOnActionClick: true })
    .catch((error) => console.error('PromptGuard SidePanel setup error:', error));

  console.log('PromptGuard extension installed successfully.');
});

// Fallback listener for action click if setPanelBehavior is unsupported in older Chromium
chrome.action.onClicked.addListener((tab) => {
  if (chrome.sidePanel && chrome.sidePanel.open) {
    chrome.sidePanel.open({ windowId: tab.windowId }).catch((err) => {
      console.warn('Could not open side panel:', err);
    });
  }
});
