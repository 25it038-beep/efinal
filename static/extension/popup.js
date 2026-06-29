document.addEventListener('DOMContentLoaded', () => {
  const emailText = document.getElementById('email-text');
  const scanBtn = document.getElementById('scan-btn');
  const resetBtn = document.getElementById('reset-btn');
  const sourceBadge = document.getElementById('source-badge');
  
  const inputView = document.getElementById('input-view');
  const loadingView = document.getElementById('loading-view');
  const resultView = document.getElementById('result-view');
  
  const resultBanner = document.getElementById('result-banner');
  const resultStatus = document.getElementById('result-status');
  const resultRisk = document.getElementById('result-risk');
  const resultShield = document.getElementById('result-shield');
  const resultExplanation = document.getElementById('result-explanation');
  const resultIndicators = document.getElementById('result-indicators');

  // API Endpoint
  const API_URL = 'https://finalcheck-1.onrender.com/api/predict';

  // Check if there is selected text from context menu
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['selectedText', 'autoScan'], (data) => {
      if (data.selectedText) {
        emailText.value = data.selectedText;
        sourceBadge.style.display = 'block';
        
        // Clear the notification badge
        chrome.action.setBadgeText({ text: "" });
        
        // Auto scan if triggered from context menu
        if (data.autoScan) {
          // Clear autoScan flag so it doesn't loop
          chrome.storage.local.set({ autoScan: false });
          performScan(data.selectedText);
        }
      }
    });
  }

  scanBtn.addEventListener('click', () => {
    const text = emailText.value.trim();
    if (!text) {
      alert('Please enter or select some email text to analyze.');
      return;
    }
    performScan(text);
  });

  resetBtn.addEventListener('click', () => {
    emailText.value = '';
    sourceBadge.style.display = 'none';
    
    // Clear storage
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.remove(['selectedText', 'autoScan']);
    }
    
    resultView.style.display = 'none';
    inputView.style.display = 'block';
  });

  async function performScan(text) {
    // Show loading
    inputView.style.display = 'none';
    resultView.style.display = 'none';
    loadingView.style.display = 'block';

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text: text })
      });

      if (!response.ok) {
        throw new Error(`Server returned status: ${response.status}`);
      }

      const data = await response.json();
      displayResults(data);
    } catch (err) {
      console.error(err);
      alert('Failed to connect to the phishing detector backend. Ensure the server is running at https://finalcheck-1.onrender.com');
      
      // Go back to input
      loadingView.style.display = 'none';
      inputView.style.display = 'block';
    }
  }

  function displayResults(data) {
    loadingView.style.display = 'none';
    resultView.style.display = 'block';

    // Set Status & Score
    resultStatus.innerText = data.classification.toUpperCase();
    resultRisk.innerText = data.risk_score;
    resultExplanation.innerText = data.explanation;

    // Reset banner classes
    resultBanner.className = 'result-banner';
    
    if (data.classification === 'Phishing') {
      resultBanner.classList.add('bg-red');
      resultShield.innerText = '🚨';
    } else if (data.classification === 'Suspicious') {
      resultBanner.classList.add('bg-yellow');
      resultShield.innerText = '⚠️';
    } else {
      resultBanner.classList.add('bg-green');
      resultShield.innerText = '🛡️';
    }

    // Populate Indicators
    resultIndicators.innerHTML = '';
    let triggeredCount = 0;

    for (const [key, triggered] of Object.entries(data.detected_indicators)) {
      if (triggered) {
        triggeredCount++;
        const label = key.replace('_', ' ').toUpperCase();
        const badge = document.createElement('span');
        badge.className = 'badge badge-red';
        badge.innerText = label;
        resultIndicators.appendChild(badge);
      }
    }

    if (triggeredCount === 0) {
      const badge = document.createElement('span');
      badge.className = 'badge badge-green';
      badge.innerText = 'NO THREAT INDICATORS DETECTED';
      resultIndicators.appendChild(badge);
    }
  }
});
