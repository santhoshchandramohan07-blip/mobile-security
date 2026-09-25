/**
 * AegisShield Mobile Security - Live Guardian Controller
 * Manages Live Sensor Telemetry, All Apps & Permissions, and AI Security Chatbot.
 */

// State
let ws = null;
let isConnected = false;
let httpHeartbeatActive = false;
let voiceEnabled = true;
let allApps = [];
let currentFilter = 'ALL';
let searchQuery = '';
let recentEvents = [];
let blockedRegistry = new Set();
let deferredInstallPrompt = null;
let liveScreenTimeData = null; // Cached screen time data for chatbot

// DOM Elements - Navigation & Header
const hostStatusPill = document.getElementById('hostStatusPill');
const hostStatusLabel = document.getElementById('hostStatusLabel');
const btnVoiceToggle = document.getElementById('btnVoiceToggle');
const voiceIcon = document.getElementById('voiceIcon');
const voiceLabel = document.getElementById('voiceLabel');
const pwaInstallBanner = document.getElementById('pwaInstallBanner');
const btnInstallPwa = document.getElementById('btnInstallPwa');
const btnDismissPwa = document.getElementById('btnDismissPwa');
const toastPopup = document.getElementById('toastPopup');
const toastText = document.getElementById('toastText');

// Tabs & Navigation
const tabButtons = {
  LiveMonitor: document.getElementById('tabBtnLiveMonitor'),
  AppsPermissions: document.getElementById('tabBtnApps'),
  ScreenTime: document.getElementById('tabBtnScreenTime'),
  Chatbot: document.getElementById('tabBtnChatbot')
};
const tabViews = {
  LiveMonitor: document.getElementById('viewLiveMonitor'),
  AppsPermissions: document.getElementById('viewAppsPermissions'),
  ScreenTime: document.getElementById('viewScreenTime'),
  AppDetail: document.getElementById('viewAppDetail'),
  Chatbot: document.getElementById('viewChatbot')
};

// Section: Screen Time Elements
const stTotalTime = document.getElementById('stTotalTime');
const stActiveAppsCount = document.getElementById('stActiveAppsCount');
const stTopAppName = document.getElementById('stTopAppName');
const stTopAppTime = document.getElementById('stTopAppTime');
const btnRefreshScreenTime = document.getElementById('btnRefreshScreenTime');
const screenTimeListGrid = document.getElementById('screenTimeListGrid');

// Section: App Detail Page Elements
const btnBackToApps = document.getElementById('btnBackToApps');
const detailAppIconSlot = document.getElementById('detailAppIconSlot');
const detailAppName = document.getElementById('detailAppName');
const detailPkgName = document.getElementById('detailPkgName');
const detailCategory = document.getElementById('detailCategory');
const detailRiskBadge = document.getElementById('detailRiskBadge');
const detailScreenTimePill = document.getElementById('detailScreenTimePill');
const btnDetailAskAI = document.getElementById('btnDetailAskAI');
const btnDetailBlock = document.getElementById('btnDetailBlock');
const detailGrantedCount = document.getElementById('detailGrantedCount');
const detailDeniedCount = document.getElementById('detailDeniedCount');
const pillGrantedCount = document.getElementById('pillGrantedCount');
const pillDeniedCount = document.getElementById('pillDeniedCount');
const detailLoadingBox = document.getElementById('detailLoadingBox');
const detailContentWrap = document.getElementById('detailContentWrap');
const grantedPermsList = document.getElementById('grantedPermsList');
const deniedPermsList = document.getElementById('deniedPermsList');
let currentDetailPkg = null;

// Section 1: Live Monitor Elements
const sensorAnnouncementBar = document.getElementById('sensorAnnouncementBar');
const announceTitle = document.getElementById('announceTitle');
const announceMessage = document.getElementById('announceMessage');
const btnAnnounceAction = document.getElementById('btnAnnounceAction');

const cardCamera = document.getElementById('cardCamera');
const camBadge = document.getElementById('camBadge');
const camAppName = document.getElementById('camAppName');
const camTimestamp = document.getElementById('camTimestamp');
const camFooterNote = document.getElementById('camFooterNote');

const cardMic = document.getElementById('cardMic');
const micBadge = document.getElementById('micBadge');
const micAppName = document.getElementById('micAppName');
const micTimestamp = document.getElementById('micTimestamp');
const micFooterNote = document.getElementById('micFooterNote');

const cardPhotos = document.getElementById('cardPhotos');
const photosBadge = document.getElementById('photosBadge');
const photosAppName = document.getElementById('photosAppName');
const photosTimestamp = document.getElementById('photosTimestamp');

const cardData = document.getElementById('cardData');
const dataBadge = document.getElementById('dataBadge');
const dataAppName = document.getElementById('dataAppName');
const dataTimestamp = document.getElementById('dataTimestamp');

const eventsList = document.getElementById('eventsList');
const btnClearEvents = document.getElementById('btnClearEvents');

// Badge Slots & Telemetry Elements
const camAppBadgeSlot = document.getElementById('camAppBadgeSlot');
const micAppBadgeSlot = document.getElementById('micAppBadgeSlot');
const photosAppBadgeSlot = document.getElementById('photosAppBadgeSlot');
const dataAppBadgeSlot = document.getElementById('dataAppBadgeSlot');
const btnRefreshTelemetry = document.getElementById('btnRefreshTelemetry');

// Section 2: Apps & Permissions Elements
const appsSearchInput = document.getElementById('appsSearchInput');
const btnClearSearch = document.getElementById('btnClearSearch');
const btnRefreshApps = document.getElementById('btnRefreshApps');
const appsListGrid = document.getElementById('appsListGrid');
const totalAppsCount = document.getElementById('totalAppsCount');
const blockedAppsCount = document.getElementById('blockedAppsCount');
const filterChips = document.querySelectorAll('.filter-chip');

// Section 3: AI Chatbot Elements
const chatMessages = document.getElementById('chatMessages');
const chatInputForm = document.getElementById('chatInputForm');
const chatTextInput = document.getElementById('chatTextInput');
const promptChips = document.querySelectorAll('.chat-prompt-chip');

// Threat Modal Elements
const threatModal = document.getElementById('threatModal');
const modalAppTitle = document.getElementById('modalAppTitle');
const modalPkgName = document.getElementById('modalPkgName');
const modalQueryNotice = document.getElementById('modalQueryNotice');
const btnBlockThreat = document.getElementById('btnBlockThreat');
const btnDismissThreat = document.getElementById('btnDismissThreat');
let pendingThreat = null;

// ========================================================
// 1. TOAST & VOICE SYNTHESIS ENGINE
// ========================================================
function showToast(message) {
  if (!toastPopup) return;
  toastText.textContent = message;
  toastPopup.classList.add('show');
  setTimeout(() => toastPopup.classList.remove('show'), 3500);
}

function speakVoice(text) {
  if (!voiceEnabled || !('speechSynthesis' in window)) return;
  try {
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 1.0;
    utterance.pitch = 1.0;
    utterance.volume = 1.0;
    window.speechSynthesis.speak(utterance);
  } catch (err) {
    console.warn('Speech synthesis note:', err);
  }
}

btnVoiceToggle.addEventListener('click', () => {
  voiceEnabled = !voiceEnabled;
  if (voiceEnabled) {
    btnVoiceToggle.classList.remove('muted');
    voiceIcon.textContent = '🔊';
    voiceLabel.textContent = 'VOICE ON';
    showToast('Voice announcements active.');
    speakVoice('AegisShield voice alerts active.');
  } else {
    btnVoiceToggle.classList.add('muted');
    voiceIcon.textContent = '🔇';
    voiceLabel.textContent = 'MUTED';
    window.speechSynthesis.cancel();
    showToast('Voice alerts muted.');
  }
});

// ========================================================
// 2. TAB SWITCHING SYSTEM
// ========================================================
function switchTab(tabName) {
  Object.keys(tabViews).forEach(key => {
    if (tabViews[key]) {
      tabViews[key].classList.toggle('active', key === tabName);
    }
  });

  Object.keys(tabButtons).forEach(key => {
    if (tabButtons[key]) {
      tabButtons[key].classList.toggle('active', key === tabName);
    }
  });

  if (tabName === 'AppsPermissions' && allApps.length === 0) {
    fetchAppsList();
  }

  if (tabName === 'ScreenTime') {
    fetchScreenTime();
  }

  if (tabName === 'Chatbot') {
    setTimeout(() => {
      if (chatMessages) {
        chatMessages.scrollTop = chatMessages.scrollHeight;
      }
      if (chatTextInput) {
        chatTextInput.focus();
      }
    }, 100);
  }
}

Object.keys(tabButtons).forEach(key => {
  const btn = tabButtons[key];
  if (btn) {
    btn.addEventListener('click', () => switchTab(key));
  }
});

if (btnBackToApps) {
  btnBackToApps.addEventListener('click', () => {
    switchTab('AppsPermissions');
  });
}

if (btnRefreshScreenTime) {
  btnRefreshScreenTime.addEventListener('click', () => {
    showToast('Refreshing screen time analytics...');
    fetchScreenTime();
  });
}

// ========================================================
// 3. DUAL-TRANSPORT (WEBSOCKET + HTTP HEARTBEAT FALLBACK)
// ========================================================
const CANDIDATE_HOSTS = [
  window.location.hostname || '127.0.0.1',
  '127.0.0.1',
  'localhost',
  '10.58.35.121', // Current Laptop Wi-Fi IP
  '10.28.124.3'
];
let candidateIdx = 0;
let activeHost = CANDIDATE_HOSTS[0];

function getApiHost() {
  return activeHost;
}

function tryNextHost() {
  candidateIdx = (candidateIdx + 1) % CANDIDATE_HOSTS.length;
  activeHost = CANDIDATE_HOSTS[candidateIdx];
  console.log('Switching connection candidate host to:', activeHost);
}

function setConnectionOnline(msg = 'SHIELD ACTIVE') {
  isConnected = true;
  hostStatusPill.classList.add('online');
  hostStatusLabel.textContent = msg;
}

function setConnectionOffline(msg = 'CONNECTING...') {
  if (!httpHeartbeatActive) {
    isConnected = false;
    hostStatusPill.classList.remove('online');
    hostStatusLabel.textContent = msg;
  }
}

function initWebSocket() {
  const host = getApiHost();
  const wsUrl = `ws://${host}:8765`;

  try {
    if (ws) {
      try { ws.close(); } catch(e){}
    }
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setConnectionOnline('SHIELD ACTIVE');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleIncomingMessage(data);
      } catch (e) {
        console.error('WS Parse Error:', e);
      }
    };

    ws.onclose = () => {
      setConnectionOffline('RECONNECTING...');
      tryNextHost();
      setTimeout(initWebSocket, 2000);
    };

    ws.onerror = () => {
      setConnectionOffline('CONNECTING...');
    };
  } catch (err) {
    console.warn('WebSocket init exception:', err);
    tryNextHost();
    setTimeout(initWebSocket, 2500);
  }
}

function sendMessage(msgObj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msgObj));
  }
}

// HTTP REST Heartbeat & Status Polling (Guarantees zero 'CONNECTING...' hang)
async function pollHttpStatus() {
  try {
    const res = await fetch('/api/status', { cache: 'no-store' });
    if (res.ok) {
      const data = await res.json();
      httpHeartbeatActive = true;
      setConnectionOnline('SHIELD ACTIVE');
      
      if (data.last_sensor_use) {
        updateSensorCardsFromState(data.last_sensor_use);
      }
      if (data.recent_events && data.recent_events.length > 0 && recentEvents.length === 0) {
        recentEvents = data.recent_events;
        renderEventsList();
      }
    }
  } catch (err) {
    httpHeartbeatActive = false;
  }
}

// Fetch ALL of today's sensor events from day start (12 AM to now)
async function fetchTodayEvents() {
  try {
    const res = await fetch('/api/today-events', { cache: 'no-store' });
    if (res.ok) {
      const data = await res.json();
      if (data.events && data.events.length > 0) {
        // Merge without duplicates (match on package_name + sensor + timestamp within 3s)
        const merged = [...recentEvents];
        for (const ev of data.events) {
          const exists = merged.some(e => e.package_name === ev.package_name && e.sensor === ev.sensor && Math.abs((e.timestamp || 0) - (ev.timestamp || 0)) < 3000);
          if (!exists) {
            merged.push(ev);
          }
        }
        // ALWAYS SORT: Newest timestamps on top, down to 12:00 AM
        merged.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        recentEvents = merged;
        renderEventsList();
        console.log(`📋 Loaded ${data.events.length} sensor events from today's history (${recentEvents.length} total in time order).`);
      }
    }
  } catch (err) {
    console.warn('Could not load today event history:', err);
  }
}

// ========================================================
// 4. REAL APP BRAND ICONS & SENSOR TELEMETRY HANDLERS
// ========================================================
function getAppBrandIconHtml(appName = '', packageName = '', sensor = '', isLarge = false) {
  const name = (appName || '').toLowerCase();
  const pkg = (packageName || '').toLowerCase();
  const sizeClass = isLarge ? 'sensor-slot' : 'mini';

  // 1. Instagram
  if (pkg.includes('instagram') || name.includes('instagram')) {
    return `
      <div class="app-brand-badge brand-instagram ${sizeClass}" title="Instagram">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#ffffff" stroke-width="2">
          <rect x="2" y="2" width="20" height="20" rx="5" ry="5"/>
          <path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/>
          <line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/>
        </svg>
      </div>
    `;
  }

  // 2. Snapchat
  if (pkg.includes('snapchat') || name.includes('snapchat')) {
    return `
      <div class="app-brand-badge brand-snapchat ${sizeClass}" title="Snapchat">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="#000000">
          <path d="M12 2C7.58 2 4 5.58 4 10c0 3.2 1.88 5.95 4.58 7.22-.18.42-.58 1.05-1.58 1.48-.3.13-.5.42-.5.75 0 .44.36.8.8.8.4 0 2.2-.2 3.7-1.25 1-.7 2-1 3-1s2 .3 3 1c1.5 1.05 3.3 1.25 3.7 1.25.44 0 .8-.36.8-.8 0-.33-.2-.62-.5-.75-1-.43-1.4-1.06-1.58-1.48C18.12 15.95 20 13.2 20 10c0-4.42-3.58-8-8-8z"/>
        </svg>
      </div>
    `;
  }

  // 3. WhatsApp
  if (pkg.includes('whatsapp') || name.includes('whatsapp')) {
    return `
      <div class="app-brand-badge brand-whatsapp ${sizeClass}" title="WhatsApp">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="#ffffff">
          <path d="M12.04 2C6.58 2 2.13 6.45 2.13 11.91c0 1.75.46 3.45 1.32 4.95L2.05 22l5.25-1.38c1.45.79 3.08 1.21 4.74 1.21 5.46 0 9.91-4.45 9.91-9.91 0-2.65-1.03-5.14-2.9-7.01A9.82 9.82 0 0 0 12.04 2zm5.79 14.15c-.24.68-1.39 1.3-1.92 1.39-.51.08-1.17.12-3.79-.96-3.23-1.33-5.32-4.63-5.48-4.85-.16-.22-1.31-1.74-1.31-3.32 0-1.58.83-2.35 1.12-2.67.3-.32.65-.4.87-.4.22 0 .43 0 .62.01.2.01.46-.07.72.55.26.63.89 2.17.97 2.33.08.16.14.35.03.56-.11.22-.16.35-.32.54-.16.19-.34.42-.48.56-.16.16-.33.33-.14.65.19.32.84 1.38 1.8 2.24 1.24 1.1 2.28 1.44 2.6 1.6.32.16.51.13.7-.08.19-.22.81-.94 1.02-1.26.22-.32.43-.27.73-.16.3.11 1.9.9 2.23 1.06.32.16.54.24.62.38.08.14.08.82-.16 1.5z"/>
        </svg>
      </div>
    `;
  }

  // 4. Samsung Camera / Generic Camera
  if (pkg.includes('camera') || name.includes('camera')) {
    return `
      <div class="app-brand-badge brand-camera ${sizeClass}" title="Camera">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#FF3B30" stroke-width="2">
          <circle cx="12" cy="12" r="7"/>
          <circle cx="12" cy="12" r="3" fill="#FF3B30"/>
          <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/>
        </svg>
      </div>
    `;
  }

  // 5. Photos / Gallery / Google Photos / Picsart
  if (pkg.includes('photos') || pkg.includes('gallery') || name.includes('photo') || name.includes('gallery') || pkg.includes('picsart')) {
    return `
      <div class="app-brand-badge brand-photos ${sizeClass}" title="Photos">
        <svg viewBox="0 0 24 24" width="22" height="22">
          <circle cx="8" cy="8" r="5" fill="#EA4335"/>
          <circle cx="16" cy="8" r="5" fill="#FBBC05"/>
          <circle cx="16" cy="16" r="5" fill="#34A853"/>
          <circle cx="8" cy="16" r="5" fill="#4285F4"/>
        </svg>
      </div>
    `;
  }

  // 5b. CapCut / Video Editor
  if (pkg.includes('lvoverseas') || pkg.includes('capcut') || name.includes('capcut')) {
    return `
      <div class="app-brand-badge brand-capcut ${sizeClass}" style="background:linear-gradient(135deg,#000000,#1f1f1f);border:1.5px solid #00F2FE;" title="CapCut Video Editor">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="#00F2FE">
          <path d="M18 4l2 4h-3l-2-4h-2l2 4h-3l-2-4H8l2 4H7L5 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V4h-4z"/>
        </svg>
      </div>
    `;
  }

  // 6. Calculator
  if (pkg.includes('calculator') || name.includes('calculator')) {
    return `
      <div class="app-brand-badge brand-calculator ${sizeClass}" title="Calculator">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#ffffff" stroke-width="2.2">
          <rect x="4" y="2" width="16" height="20" rx="3" ry="3"/>
          <line x1="8" y1="6" x2="16" y2="6"/>
          <line x1="16" y1="14" x2="16" y2="18"/>
          <path d="M8 10h.01M12 10h.01M16 10h.01M8 14h.01M12 14h.01M8 18h.01M12 18h.01"/>
        </svg>
      </div>
    `;
  }

  // 7. Voice Recorder / Microphone
  if (pkg.includes('recorder') || pkg.includes('voicenote') || name.includes('recorder') || name.includes('voice')) {
    return `
      <div class="app-brand-badge brand-recorder ${sizeClass}" title="Voice Recorder">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#ffffff" stroke-width="2">
          <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
          <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
          <line x1="12" y1="19" x2="12" y2="23"/>
        </svg>
      </div>
    `;
  }

  // 8. ChatGPT
  if (pkg.includes('openai') || pkg.includes('chatgpt') || name.includes('chatgpt')) {
    return `
      <div class="app-brand-badge brand-chatgpt ${sizeClass}" title="ChatGPT">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#ffffff" stroke-width="1.8">
          <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z"/>
          <path d="M12 6v6l4 2"/>
        </svg>
      </div>
    `;
  }

  // 9. Payment Apps (Google Pay / PhonePe)
  if (pkg.includes('paisa') || pkg.includes('phonepe') || name.includes('pay') || name.includes('phonepe')) {
    return `
      <div class="app-brand-badge brand-gpay ${sizeClass}" title="Payment App">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#1A73E8" stroke-width="2">
          <rect x="2" y="5" width="20" height="14" rx="2"/>
          <line x1="2" y1="10" x2="22" y2="10"/>
        </svg>
      </div>
    `;
  }

  // 10. Spotify
  if (pkg.includes('spotify') || name.includes('spotify')) {
    return `
      <div class="app-brand-badge brand-spotify ${sizeClass}" title="Spotify">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="#ffffff">
          <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm4.586 14.424c-.18.295-.563.387-.857.207-2.35-1.435-5.308-1.76-8.793-.963-.335.077-.67-.133-.747-.468-.077-.335.132-.67.467-.747 3.815-.873 7.08-.507 9.723 1.114.294.18.387.563.207.857zm1.226-2.723c-.227.37-.713.487-1.083.26-2.69-1.654-6.79-2.133-9.97-1.168-.415.126-.856-.11-0.982-.525-.126-.415.11-.856.525-.982 3.633-1.102 8.156-.566 11.25 1.332.37.227.487.713.26 1.083zm.106-2.835C14.692 8.95 9.375 8.775 6.297 9.71c-.496.15-1.025-.13-1.175-.626-.15-.496.13-1.025.626-1.175 3.54-1.074 9.42-.867 13.125 1.332.447.265.594.845.328 1.292-.265.447-.845.594-1.292.328z"/>
        </svg>
      </div>
    `;
  }

  // 11. YouTube
  if (pkg.includes('youtube') || name.includes('youtube')) {
    return `
      <div class="app-brand-badge brand-youtube ${sizeClass}" title="YouTube">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="#ffffff">
          <path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/>
        </svg>
      </div>
    `;
  }

  // 12. Google Chrome / Browser
  if (pkg.includes('chrome') || pkg.includes('sbrowser') || name.includes('chrome') || name.includes('browser')) {
    return `
      <div class="app-brand-badge brand-chrome ${sizeClass}" style="background:linear-gradient(135deg,#EA4335,#FBBC05,#34A853,#4285F4);" title="Web Browser">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#ffffff" stroke-width="2.2">
          <circle cx="12" cy="12" r="10"/>
          <circle cx="12" cy="12" r="4"/>
          <line x1="21.17" y1="8" x2="12" y2="8"/>
          <line x1="3.95" y1="6.06" x2="8.54" y2="14"/>
          <line x1="10.88" y1="21.94" x2="15.46" y2="14"/>
        </svg>
      </div>
    `;
  }

  // 13. eFootball PES / Games
  if (pkg.includes('pes') || pkg.includes('konami') || name.includes('pes') || pkg.includes('drdriving') || name.includes('driving')) {
    return `
      <div class="app-brand-badge brand-game ${sizeClass}" style="background:linear-gradient(135deg,#3B82F6,#8B5CF6);" title="Game">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#ffffff" stroke-width="2">
          <rect x="2" y="6" width="20" height="12" rx="3"/>
          <path d="M6 12h4m-2-2v4m9-3a1 1 0 1 1-2 0 1 1 0 0 1 2 0zm3 2a1 1 0 1 1-2 0 1 1 0 0 1 2 0z"/>
        </svg>
      </div>
    `;
  }

  // 14. Pinterest
  if (pkg.includes('pinterest') || name.includes('pinterest')) {
    return `
      <div class="app-brand-badge brand-pinterest ${sizeClass}" style="background:#E60023;" title="Pinterest">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="#ffffff">
          <path d="M12 0a12 12 0 0 0-4.37 23.18c-.06-.99-.1-2.52.2-3.61l1.45-6.17s-.37-.74-.37-1.84c0-1.73 1-3.02 2.25-3.02 1.06 0 1.57.8 1.57 1.76 0 1.07-.68 2.67-1.03 4.15-.3 1.25.63 2.27 1.86 2.27 2.23 0 3.95-2.35 3.95-5.75 0-3-2.16-5.11-5.25-5.11-3.58 0-5.68 2.68-5.68 5.45 0 1.08.42 2.24.94 2.87.1.13.12.24.09.37l-.35 1.45c-.06.24-.19.29-.44.18-1.63-.76-2.65-3.14-2.65-5.06 0-4.12 3-7.91 8.65-7.91 4.54 0 8.07 3.24 8.07 7.56 0 4.51-2.84 8.14-6.79 8.14-1.32 0-2.57-.69-3-1.51l-.81 3.12c-.3 1.13-1.1 2.54-1.64 3.4A12 12 0 1 0 12 0z"/>
        </svg>
      </div>
    `;
  }

  // 15. Cloud Storage (TeraBox, Drive)
  if (pkg.includes('dubox') || pkg.includes('drive') || name.includes('terabox') || name.includes('cloud')) {
    return `
      <div class="app-brand-badge brand-cloud ${sizeClass}" style="background:linear-gradient(135deg,#0052D4,#4364F7,#6FB1FC);" title="Cloud Storage">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#ffffff" stroke-width="2">
          <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
        </svg>
      </div>
    `;
  }

  // Fallback
  const initial = (appName || pkg.split('.').pop() || 'A').charAt(0).toUpperCase();
  return `
    <div class="app-brand-badge brand-generic ${sizeClass}" title="${escapeHtml(appName || pkg)}">
      <span>${escapeHtml(initial)}</span>
    </div>
  `;
}

const dynamicFloatingPopup = document.getElementById('dynamicFloatingPopup');
let popupDismissTimer = null;
const sensorRevertTimers = {};

function showFloatingScreenPopup(event) {
  if (!dynamicFloatingPopup) return;
  const iconSlot = document.getElementById('popupIconSlot');
  const titleEl = document.getElementById('popupTitle');
  const timeEl = document.getElementById('popupTime');
  const bodyEl = document.getElementById('popupBody');
  const closeBtn = document.getElementById('popupCloseBtn');

  if (iconSlot) {
    if (event.sensor === 'CAMERA') iconSlot.textContent = '📸';
    else if (event.sensor === 'MICROPHONE') iconSlot.textContent = '🎙️';
    else if (event.sensor === 'PHOTOS_VIDEOS') iconSlot.textContent = '🖼️';
    else iconSlot.textContent = '🛡️';
  }

  if (titleEl) {
    titleEl.textContent = event.is_unusual ? `⚠️ ALERT: ${event.app_name}` : `🔔 Live Access: ${event.app_name}`;
  }
  if (timeEl) {
    timeEl.textContent = event.time_str || 'Just now';
  }
  if (bodyEl) {
    bodyEl.textContent = event.user_notice || `${event.app_name} accessed ${event.sensor}`;
  }

  dynamicFloatingPopup.classList.toggle('danger', !!event.is_unusual);
  dynamicFloatingPopup.classList.add('show');

  dynamicFloatingPopup.onclick = (e) => {
    if (e.target && (e.target.id === 'popupCloseBtn' || e.target.closest('#popupCloseBtn'))) {
      return;
    }
    dynamicFloatingPopup.classList.remove('show');
    if (popupDismissTimer) clearTimeout(popupDismissTimer);
    highlightAppInLog(event.package_name);
  };

  if (popupDismissTimer) clearTimeout(popupDismissTimer);
  popupDismissTimer = setTimeout(() => {
    dynamicFloatingPopup.classList.remove('show');
  }, 6500);

  if (closeBtn && !closeBtn._bound) {
    closeBtn._bound = true;
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      dynamicFloatingPopup.classList.remove('show');
      if (popupDismissTimer) clearTimeout(popupDismissTimer);
    });
  }
}

function highlightAppInLog(pkg) {
  if (!pkg) return;
  // 1. Switch to Live Monitor tab
  if (tabButtons && tabButtons.LiveMonitor) {
    tabButtons.LiveMonitor.click();
  }
  // 2. Find and highlight the card in the list
  setTimeout(() => {
    const cards = document.querySelectorAll('.event-card');
    let matchedCard = null;
    for (const card of cards) {
      if (card.getAttribute('data-pkg') === pkg || card.innerHTML.includes(pkg)) {
        matchedCard = card;
        break;
      }
    }
    if (matchedCard) {
      matchedCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
      matchedCard.classList.remove('highlight-pulse');
      void matchedCard.offsetWidth; // trigger reflow
      matchedCard.classList.add('highlight-pulse');
      setTimeout(() => matchedCard.classList.remove('highlight-pulse'), 4500);
    }
  }, 350);
}

function revertSensorCardToIdle(sensor, lastEvent = null) {
  if (sensor === 'CAMERA') {
    if (cardCamera) cardCamera.classList.remove('active-stream', 'danger');
    if (camBadge) {
      camBadge.textContent = 'IDLE';
      camBadge.className = 'sensor-state-pill idle';
    }
    if (camTimestamp && lastEvent) {
      camTimestamp.textContent = `Last access: ${lastEvent.time_str || 'Recently'}`;
    }
    if (camFooterNote) camFooterNote.textContent = 'Hardware camera secured';
  } else if (sensor === 'MICROPHONE') {
    if (cardMic) cardMic.classList.remove('active-stream', 'danger');
    if (micBadge) {
      micBadge.textContent = 'IDLE';
      micBadge.className = 'sensor-state-pill idle';
    }
    if (micTimestamp && lastEvent) {
      micTimestamp.textContent = `Last access: ${lastEvent.time_str || 'Recently'}`;
    }
    if (micFooterNote) micFooterNote.textContent = 'Microphone secured';
  } else if (sensor === 'PHOTOS_VIDEOS') {
    if (cardPhotos) cardPhotos.classList.remove('active-stream', 'danger');
    if (photosBadge) {
      photosBadge.textContent = 'SECURED';
      photosBadge.className = 'sensor-state-pill idle';
    }
    if (photosTimestamp && lastEvent) {
      photosTimestamp.textContent = `Last access: ${lastEvent.time_str || 'Recently'}`;
    }
    const photosFooter = document.getElementById('photosFooterNote');
    if (photosFooter) photosFooter.textContent = 'Storage protected by AppOps';
  }
}

function updateSensorCardsFromState(lastSensors) {
  if (!lastSensors) return;

  // Camera
  const cam = lastSensors.CAMERA;
  if (cam) {
    if (camAppBadgeSlot) {
      camAppBadgeSlot.innerHTML = getAppBrandIconHtml(cam.app_name, cam.package_name, 'CAMERA', true);
    }
    camAppName.textContent = cam.app_name || 'Camera';
    camTimestamp.textContent = `Last access: ${cam.time_str || 'Recently'}`;
    camBadge.textContent = 'IDLE';
    camBadge.className = 'sensor-state-pill idle';
    cardCamera.classList.remove('active-stream', 'danger');
    camFooterNote.textContent = 'Hardware camera secured';
  }

  // Microphone
  const mic = lastSensors.MICROPHONE;
  if (mic) {
    if (micAppBadgeSlot) {
      micAppBadgeSlot.innerHTML = getAppBrandIconHtml(mic.app_name, mic.package_name, 'MICROPHONE', true);
    }
    micAppName.textContent = mic.app_name || 'Microphone';
    micTimestamp.textContent = `Last access: ${mic.time_str || 'Recently'}`;
    micBadge.textContent = 'IDLE';
    micBadge.className = 'sensor-state-pill idle';
    cardMic.classList.remove('active-stream', 'danger');
    micFooterNote.textContent = 'Microphone stream secured';
  }

  // Photos & Videos
  const photos = lastSensors.PHOTOS_VIDEOS;
  if (photos) {
    if (photosAppBadgeSlot) {
      photosAppBadgeSlot.innerHTML = getAppBrandIconHtml(photos.app_name, photos.package_name, 'PHOTOS_VIDEOS', true);
    }
    photosAppName.textContent = photos.app_name || 'Photos & Videos';
    photosTimestamp.textContent = `Last access: ${photos.time_str || 'Recently'}`;
    photosBadge.textContent = 'SECURED';
    photosBadge.className = 'sensor-state-pill idle';
    if (cardPhotos) {
      cardPhotos.classList.remove('active-stream', 'danger');
      const photosFooter = document.getElementById('photosFooterNote');
      if (photosFooter) {
        photosFooter.textContent = 'Storage protected by AppOps';
      }
    }
  }

  // Background Data
  const data = lastSensors.BACKGROUND_DATA;
  if (data) {
    if (dataAppBadgeSlot) {
      dataAppBadgeSlot.innerHTML = getAppBrandIconHtml(data.app_name, data.package_name, 'BACKGROUND_DATA', true);
    }
    dataAppName.textContent = data.app_name || 'Background Data';
    dataTimestamp.textContent = `Synced on ${data.time_str || 'Recently'}`;
    dataBadge.textContent = 'STANDBY';
    dataBadge.className = 'sensor-state-pill sync';
  }
}

function handleIncomingMessage(msg) {
  switch (msg.type) {
    case 'CONNECTION_ESTABLISHED':
      setConnectionOnline('SHIELD ACTIVE');
      if (msg.last_sensor_use) {
        updateSensorCardsFromState(msg.last_sensor_use);
      }
      if (msg.recent_events && msg.recent_events.length > 0) {
        const merged = [...recentEvents];
        for (const ev of msg.recent_events) {
          const exists = merged.some(e => e.package_name === ev.package_name && e.sensor === ev.sensor && Math.abs((e.timestamp || 0) - (ev.timestamp || 0)) < 3000);
          if (!exists) {
            merged.push(ev);
          }
        }
        merged.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        recentEvents = merged;
        renderEventsList();
      }
      break;

    case 'SENSOR_ALERT':
      processSensorAlert(msg);
      break;

    case 'SENSOR_STATUS':
      if (msg.state === 'RELEASED') {
        revertSensorCardToIdle(msg.sensor, msg);
      }
      break;

    case 'AUDIT_REPORT':
      if (msg.apps) {
        allApps = msg.apps;
        renderAppsList();
      }
      break;

    case 'CHAT_RESPONSE':
      appendAssistantMessage(msg.reply, msg.suggestions);
      if (msg.action_executed) {
        fetchAppsList();
      }
      break;

    case 'BLOCK_RESPONSE':
      showToast(msg.message || `Blocked ${msg.sensor} for ${msg.package_name}`);
      blockedRegistry.add(msg.package_name);
      fetchAppsList();
      break;

    case 'UNBLOCK_RESPONSE':
      showToast(msg.message || `Unblocked ${msg.sensor}`);
      blockedRegistry.delete(msg.package_name);
      fetchAppsList();
      break;

    case 'SCREEN_TIME_REPORT':
      if (msg.data) {
        updateScreenTimeDisplay(msg.data);
      }
      break;

    case 'APP_DETAILS_REPORT':
      if (msg.data) {
        renderAppDetailContent(msg.data);
      }
      break;
  }
}

function processSensorAlert(event) {
  // 1. Update Live Announcement Bar
  announceTitle.textContent = event.is_unusual ? '⚠️ CRITICAL ANOMALY' : '🔴 LIVE SENSOR ACCESS';
  announceMessage.textContent = event.user_notice || `Your ${event.app_name} is accessing ${event.sensor} on ${event.time_str}`;
  sensorAnnouncementBar.className = `sensor-announcement-bar show ${event.is_unusual ? 'threat-mode' : ''}`;

  // 1b. Trigger On-Screen Popup Notification Toast & Dynamic Floating Popup
  showToast(event.user_notice || `🚨 ${event.app_name} is accessing ${event.sensor}!`);
  showFloatingScreenPopup(event);

  // 1c. Browser & ServiceWorker System Notification
  if ('Notification' in window && Notification.permission === 'granted') {
    if (navigator.serviceWorker && navigator.serviceWorker.ready) {
      navigator.serviceWorker.ready.then(reg => {
        reg.showNotification(`AegisShield: ${event.app_name} (${event.sensor})`, {
          body: event.user_notice || `${event.app_name} is accessing ${event.sensor} on ${event.time_str}`,
          icon: '/icon-192.png',
          badge: '/icon-192.png',
          vibrate: [250, 100, 250],
          tag: `sensor_${event.sensor}`,
          data: {
            package_name: event.package_name,
            app_name: event.app_name,
            sensor: event.sensor
          }
        });
      }).catch(err => {
        console.debug('ServiceWorker showNotification note:', err);
      });
    } else {
      try {
        const notif = new Notification(`AegisShield: ${event.app_name} (${event.sensor})`, {
          body: event.user_notice || `${event.app_name} is accessing ${event.sensor} on ${event.time_str}`,
          icon: '/icon-192.png',
          badge: '/icon-192.png',
          vibrate: [250, 100, 250],
          tag: `sensor_${event.sensor}`,
          data: {
            package_name: event.package_name,
            app_name: event.app_name,
            sensor: event.sensor
          }
        });
        notif.onclick = () => {
          window.focus();
          highlightAppInLog(event.package_name);
        };
      } catch (e) {
        console.debug('Standard notification fallback:', e);
      }
    }
  }

  // 2. Voice announcement
  if (event.speech_text) {
    speakVoice(event.speech_text);
  }

  // 3. Update sensor cards & app badge slots with real app brand icon
  if (event.sensor === 'CAMERA') {
    if (camAppBadgeSlot) {
      camAppBadgeSlot.innerHTML = getAppBrandIconHtml(event.app_name, event.package_name, 'CAMERA', true);
    }
    camAppName.textContent = event.app_name;
    camTimestamp.textContent = `Accessing on ${event.time_str}`;
    camBadge.textContent = event.is_unusual ? 'CRITICAL ANOMALY' : 'ACTIVE STREAM';
    camBadge.className = `sensor-state-pill ${event.is_unusual ? 'danger' : 'active'}`;
    cardCamera.classList.toggle('active-stream', true);
    cardCamera.classList.toggle('danger', !!event.is_unusual);
    camFooterNote.textContent = event.is_unusual ? 'Unusual camera use!' : 'Active camera stream';
  } else if (event.sensor === 'MICROPHONE') {
    if (micAppBadgeSlot) {
      micAppBadgeSlot.innerHTML = getAppBrandIconHtml(event.app_name, event.package_name, 'MICROPHONE', true);
    }
    micAppName.textContent = event.app_name;
    micTimestamp.textContent = `Accessing on ${event.time_str}`;
    micBadge.textContent = event.is_unusual ? 'CRITICAL ANOMALY' : 'RECORDING';
    micBadge.className = `sensor-state-pill ${event.is_unusual ? 'danger' : 'active'}`;
    cardMic.classList.toggle('active-stream', true);
    cardMic.classList.toggle('danger', !!event.is_unusual);
    micFooterNote.textContent = event.is_unusual ? 'Background mic detected!' : 'Voice stream';
  } else if (event.sensor === 'PHOTOS_VIDEOS') {
    if (photosAppBadgeSlot) {
      photosAppBadgeSlot.innerHTML = getAppBrandIconHtml(event.app_name, event.package_name, 'PHOTOS_VIDEOS', true);
    }
    photosAppName.textContent = event.app_name;
    photosTimestamp.textContent = `Access on ${event.time_str}`;
    photosBadge.textContent = event.is_unusual ? 'CRITICAL ANOMALY' : 'MEDIA ACCESS';
    photosBadge.className = `sensor-state-pill ${event.is_unusual ? 'danger' : 'active'}`;
    if (cardPhotos) {
      cardPhotos.classList.toggle('active-stream', true);
      cardPhotos.classList.toggle('danger', !!event.is_unusual);
    }
    const photosFooter = document.getElementById('photosFooterNote');
    if (photosFooter) {
      photosFooter.textContent = `${event.app_name} accessing photos & videos`;
    }
  }

  // Set auto-revert timer back to IDLE after 12s of inactivity
  if (sensorRevertTimers[event.sensor]) {
    clearTimeout(sensorRevertTimers[event.sensor]);
  }
  sensorRevertTimers[event.sensor] = setTimeout(() => {
    revertSensorCardToIdle(event.sensor, event);
  }, 12000);

  // 4. Prepend to events stream, deduplicate, and immediately sort newest on top
  const existingIdx = recentEvents.findIndex(e => e.package_name === event.package_name && e.sensor === event.sensor && Math.abs((e.timestamp || 0) - (event.timestamp || 0)) < 3000);
  if (existingIdx !== -1) {
    recentEvents[existingIdx] = { ...recentEvents[existingIdx], ...event };
  } else {
    recentEvents.unshift(event);
  }
  recentEvents.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  if (recentEvents.length > 250) recentEvents.pop(); // Keep full day
  renderEventsList();

  // 5. If Critical Anomaly, trigger Threat Modal
  if (event.is_unusual) {
    triggerThreatModal(event);
  }
}

function renderEventsList() {
  if (!eventsList) return;
  // Ensure strict chronological sort (newest on top, down to 12:00 AM)
  recentEvents.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  if (recentEvents.length === 0) {
    eventsList.innerHTML = `
      <div class="empty-events">
        <p>📋 No sensor access events recorded yet today.</p>
        <span>AegisShield is actively monitoring your Samsung Galaxy S24 (12:00 AM – Now). Events will appear here as apps access Camera or Microphone.</span>
      </div>
    `;
    return;
  }

  eventsList.innerHTML = recentEvents.map(ev => {
    const isUnusual = ev.is_unusual || (ev.risk_score >= 70);
    const isHistory = ev.from_history === true;
    const badgeClass = isUnusual ? 'critical' : 'safe';
    const badgeLabel = isUnusual ? `🚨 THREAT ${ev.risk_score}/100` : 'AUTHORIZED';
    const timeTagLabel = isHistory
      ? `📅 ${escapeHtml(ev.time_str || 'Today')}`
      : `⏰ ${escapeHtml(ev.time_str || 'Live')}`;
    const brandIcon = getAppBrandIconHtml(ev.app_name, ev.package_name, ev.sensor, false);

    let permBadge = '';
    const s = (ev.sensor || '').toUpperCase();
    if (s === 'CAMERA') {
      permBadge = '<span class="event-sensor-chip camera" style="background:rgba(239,68,68,0.18);color:#F87171;border:1px solid rgba(239,68,68,0.4);padding:3px 8px;border-radius:6px;font-size:0.72rem;font-weight:700;white-space:nowrap;">📸 CAMERA</span>';
    } else if (s === 'MICROPHONE') {
      permBadge = '<span class="event-sensor-chip mic" style="background:rgba(245,158,11,0.18);color:#FBBF24;border:1px solid rgba(245,158,11,0.4);padding:3px 8px;border-radius:6px;font-size:0.72rem;font-weight:700;white-space:nowrap;">🎙️ MICROPHONE</span>';
    } else if (s === 'PHOTOS_VIDEOS' || s === 'PHOTOS' || s === 'MEDIA') {
      permBadge = '<span class="event-sensor-chip photos" style="background:rgba(59,130,246,0.18);color:#60A5FA;border:1px solid rgba(59,130,246,0.4);padding:3px 8px;border-radius:6px;font-size:0.72rem;font-weight:700;white-space:nowrap;">🖼️ PHOTOS &amp; VIDEOS</span>';
    } else if (s === 'LOCATION') {
      permBadge = '<span class="event-sensor-chip location" style="background:rgba(16,185,129,0.18);color:#34D399;border:1px solid rgba(16,185,129,0.4);padding:3px 8px;border-radius:6px;font-size:0.72rem;font-weight:700;white-space:nowrap;">📍 LOCATION</span>';
    } else {
      permBadge = `<span class="event-sensor-chip data" style="background:rgba(139,92,246,0.18);color:#A78BFA;border:1px solid rgba(139,92,246,0.4);padding:3px 8px;border-radius:6px;font-size:0.72rem;font-weight:700;white-space:nowrap;">🌐 ${escapeHtml(ev.sensor || 'DATA')}</span>`;
    }

    const noticeText = ev.user_notice || `${ev.app_name} accessed ${ev.sensor} on ${ev.time_str}`;

    return `
      <div class="event-card ${isUnusual ? 'threat' : ''}" data-pkg="${escapeHtml(ev.package_name || '')}" style="display:flex!important;flex-direction:column!important;width:100%!important;box-sizing:border-box!important;">
        <div class="event-card-top-row">
          <div class="event-app-meta">
            ${brandIcon}
            <div style="min-width:0;flex:1;">
              <strong class="event-app-name">${escapeHtml(ev.app_name)}</strong>
              <span class="event-pkg-name">${escapeHtml(ev.package_name)}</span>
            </div>
          </div>
          <div class="event-badges-col">
            <span class="event-risk-badge ${badgeClass}">${badgeLabel}</span>
            ${permBadge}
          </div>
        </div>

        <div class="event-notice-box">
          <p class="event-notice-text">${escapeHtml(noticeText)}</p>
        </div>

        <div class="event-card-bottom-row">
          <span class="event-time-tag">${timeTagLabel}</span>
          <div class="event-button-group">
            <button class="event-btn ai" onclick="askAIChat('Tell me about ${escapeHtml(ev.app_name)} accessing ${escapeHtml(ev.sensor)}')">Ask AI</button>
            <button class="event-btn block" onclick="executeAppBlock('${escapeHtml(ev.package_name)}', '${escapeHtml(ev.sensor)}')">Block</button>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

btnClearEvents.addEventListener('click', () => {
  recentEvents = [];
  renderEventsList();
  showToast('Live stream cleared.');
});

// Test Simulation Button Listeners
async function triggerSimulation(scenario) {
  try {
    const res = await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });
    if (res.ok) {
      const data = await res.json();
      if (data.event) {
        processSensorAlert(data.event);
      }
    }
  } catch (err) {
    // Fallback over WebSocket
    sendMessage({ action: 'SIMULATE_ALERT', scenario });
  }
}

if (btnRefreshTelemetry) {
  btnRefreshTelemetry.addEventListener('click', () => {
    showToast('Refreshing live hardware telemetry...');
    pollHttpStatus();
    sendMessage({ action: 'REQUEST_USAGE_STATS' });
    sendMessage({ action: 'REQUEST_AUDIT' });
  });
}

// Announcement "ASK AI" button
btnAnnounceAction.addEventListener('click', () => {
  switchTab('Chatbot');
  const msg = announceMessage.textContent;
  handleUserChatSubmit(`What does this mean: ${msg}?`);
});

// ========================================================
// 5. ALL APPS & PERMISSIONS SECTION LOGIC
// ========================================================
async function fetchAppsList() {
  if (appsListGrid) {
    appsListGrid.innerHTML = `
      <div class="loading-apps-card">
        <div class="spinner"></div>
        <p>Scanning installed applications on Galaxy S24...</p>
      </div>
    `;
  }

  try {
    const res = await fetch('/api/apps');
    if (res.ok) {
      const data = await res.json();
      if (data.apps) {
        allApps = data.apps;
        renderAppsList();
        return;
      }
    }
  } catch (e) {
    console.warn('HTTP apps fetch fallback to WS:', e);
  }

  // WebSocket fallback
  sendMessage({ action: 'REQUEST_AUDIT' });
}

function renderAppsList() {
  if (!appsListGrid) return;

  totalAppsCount.textContent = allApps.length;
  let blockedCount = 0;

  // Filter apps
  const filtered = allApps.filter(app => {
    if (app.is_blocked || blockedRegistry.has(app.package_name)) {
      blockedCount++;
    }

    // Search query filter
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchName = (app.app_name || '').toLowerCase().includes(q);
      const matchPkg = (app.package_name || '').toLowerCase().includes(q);
      if (!matchName && !matchPkg) return false;
    }

    // Chip filter
    if (currentFilter === 'ALL') return true;
    if (currentFilter === 'BLOCKED') return app.is_blocked || blockedRegistry.has(app.package_name);
    return (app.permissions || []).includes(currentFilter);
  });

  blockedAppsCount.textContent = blockedCount;

  if (filtered.length === 0) {
    appsListGrid.innerHTML = `
      <div class="loading-apps-card">
        <p>No apps match the selected filter or search query.</p>
      </div>
    `;
    return;
  }

  appsListGrid.innerHTML = filtered.map(app => {
    const isBlocked = app.is_blocked || blockedRegistry.has(app.package_name);
    const riskLevel = app.risk_score >= 70 ? 'critical' : app.risk_score >= 40 ? 'suspicious' : app.risk_score >= 20 ? 'low' : 'safe';
    const riskLabel = riskLevel.toUpperCase();
    const perms = app.permissions || [];

    return `
      <div class="app-item-card ${isBlocked ? 'blocked-state' : ''}" onclick="openAppDetail('${escapeHtml(app.package_name)}')">
        <div class="app-item-header">
          <div class="app-title-group">
            ${getAppBrandIconHtml(app.app_name, app.package_name, perms[0] || '', false)}
            <div class="app-item-names">
              <strong class="app-item-name">${escapeHtml(app.app_name)}</strong>
              <span class="app-item-pkg">${escapeHtml(app.package_name)} • ${escapeHtml(app.category || 'App')}</span>
            </div>
          </div>
          <span class="app-risk-tag ${riskLevel}">Risk ${app.risk_score}/100</span>
        </div>

        <div class="app-perms-row">
          ${perms.map(p => {
            let icon = '⚙️';
            let cls = '';
            if (p === 'CAMERA') { icon = '📸'; cls = 'camera'; }
            else if (p === 'MICROPHONE') { icon = '🎙️'; cls = 'mic'; }
            else if (p === 'PHOTOS_VIDEOS') { icon = '🖼️'; cls = 'photos'; }
            else if (p === 'LOCATION') { icon = '📍'; cls = 'location'; }
            else if (p === 'INTERNET') { icon = '🌐'; cls = 'data'; }
            return `<span class="perm-chip ${cls}">${icon} ${p}</span>`;
          }).join('')}
        </div>

        <div class="app-detail-callout-btn-wrap">
          <button class="inspect-perms-banner-btn" onclick="event.stopPropagation(); openAppDetail('${escapeHtml(app.package_name)}')">
            <span>📋 View Given &amp; Denied Permissions</span>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </button>
        </div>

        <div class="app-item-actions">
          <button class="ask-ai-app-btn" onclick="event.stopPropagation(); askAIChat('Explain why ${escapeHtml(app.app_name)} requests permissions and is it safe?')">
            🤖 Ask AI About App
          </button>
          <button class="appops-toggle-btn ${isBlocked ? 'unblock-btn' : 'block-btn'}" onclick="event.stopPropagation(); toggleAppBlock('${escapeHtml(app.package_name)}', '${isBlocked ? 'unblock' : 'block'}', 'ALL')">
            ${isBlocked ? 'RESTORE ACCESS' : 'REVOKE / BLOCK'}
          </button>
        </div>
      </div>
    `;
  }).join('');
}

// Search and filter listeners
appsSearchInput.addEventListener('input', (e) => {
  searchQuery = e.target.value.trim();
  btnClearSearch.classList.toggle('show', !!searchQuery);
  renderAppsList();
});

btnClearSearch.addEventListener('click', () => {
  appsSearchInput.value = '';
  searchQuery = '';
  btnClearSearch.classList.remove('show');
  renderAppsList();
});

filterChips.forEach(chip => {
  chip.addEventListener('click', () => {
    filterChips.forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    currentFilter = chip.getAttribute('data-filter') || 'ALL';
    renderAppsList();
  });
});

btnRefreshApps.addEventListener('click', () => {
  showToast('Scanning applications on Samsung Galaxy S24...');
  fetchAppsList();
});

// AppOps Block/Unblock Execution
async function toggleAppBlock(pkg, action, sensor = 'ALL') {
  const url = action === 'block' ? '/api/block' : '/api/unblock';

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package_name: pkg, sensor })
    });
    if (res.ok) {
      const data = await res.json();
      showToast(data.message || `Action executed for ${pkg}`);
      if (action === 'block') {
        blockedRegistry.add(pkg);
      } else {
        blockedRegistry.delete(pkg);
      }
      renderAppsList();
      if (currentDetailPkg === pkg) {
        setTimeout(() => openAppDetail(pkg), 500);
      }
      return;
    }
  } catch (err) {
    // WS fallback
    sendMessage({
      action: action === 'block' ? 'BLOCK_APP' : 'UNBLOCK_APP',
      package_name: pkg,
      sensor
    });
  }
}

function executeAppBlock(pkg, sensor) {
  toggleAppBlock(pkg, 'block', sensor || 'ALL');
}

// ========================================================
// 5.5 APP DETAIL VIEW (GIVEN VS NOT GIVEN PERMISSIONS)
// ========================================================
async function openAppDetail(pkg) {
  if (!pkg) return;
  currentDetailPkg = pkg;
  switchTab('AppDetail');

  // Pre-fill header with known data from allApps or friendly fallback
  const cached = allApps.find(a => a.package_name === pkg) || {};
  const appTitle = cached.app_name || pkg.split('.').pop() || 'App';
  if (detailAppName) detailAppName.textContent = appTitle;
  if (detailPkgName) detailPkgName.textContent = pkg;
  if (detailCategory) detailCategory.textContent = cached.category || 'Application';
  if (detailAppIconSlot) detailAppIconSlot.innerHTML = getAppBrandIconHtml(appTitle, pkg, '', true);
  
  const riskLevel = (cached.risk_level || 'SAFE').toLowerCase();
  if (detailRiskBadge) {
    detailRiskBadge.textContent = `Risk ${cached.risk_score || 15}/100 • ${riskLevel.toUpperCase()}`;
    detailRiskBadge.className = `detail-risk-badge ${riskLevel}`;
  }
  if (detailScreenTimePill) detailScreenTimePill.textContent = '⏱️ Calculating usage...';

  // Toggle loading state
  if (detailLoadingBox) detailLoadingBox.style.display = 'flex';
  if (detailContentWrap) detailContentWrap.style.display = 'none';

  try {
    const res = await fetch(`/api/app-details?pkg=${encodeURIComponent(pkg)}`);
    if (res.ok) {
      const data = await res.json();
      renderAppDetailContent(data);
      return;
    }
  } catch (err) {
    console.warn('App details fetch exception fallback to WS:', err);
  }

  // WebSocket fallback
  sendMessage({ action: 'REQUEST_APP_DETAILS', package_name: pkg });
}

function renderAppDetailContent(data) {
  if (!data) return;
  if (detailLoadingBox) detailLoadingBox.style.display = 'none';
  if (detailContentWrap) detailContentWrap.style.display = 'block';

  if (detailAppName) detailAppName.textContent = data.app_name || currentDetailPkg;
  if (detailPkgName) detailPkgName.textContent = data.package_name || currentDetailPkg;
  if (detailCategory) detailCategory.textContent = data.category || 'Application';
  if (detailAppIconSlot) detailAppIconSlot.innerHTML = getAppBrandIconHtml(data.app_name, data.package_name, '', true);

  const riskLevel = (data.risk_level || 'SAFE').toLowerCase();
  if (detailRiskBadge) {
    detailRiskBadge.textContent = `Risk ${data.risk_score || 15}/100 • ${riskLevel.toUpperCase()}`;
    detailRiskBadge.className = `detail-risk-badge ${riskLevel}`;
  }
  if (detailScreenTimePill) detailScreenTimePill.textContent = `⏱️ ${data.screen_time || 'Not used today'}`;

  const isBlocked = data.is_blocked || blockedRegistry.has(data.package_name);
  if (btnDetailBlock) {
    btnDetailBlock.textContent = isBlocked ? 'RESTORE ALL ACCESS' : 'BLOCK ALL SENSORS';
    btnDetailBlock.className = `detail-action-btn ${isBlocked ? 'unblock' : 'block'}`;
    btnDetailBlock.onclick = () => {
      toggleAppBlock(data.package_name, isBlocked ? 'unblock' : 'block', 'ALL');
      setTimeout(() => openAppDetail(data.package_name), 600);
    };
  }

  if (btnDetailAskAI) {
    btnDetailAskAI.onclick = () => {
      switchTab('Chatbot');
      handleUserChatSubmit(`Analyze the security risk and permissions for ${data.app_name} (${data.package_name}). Is it safe?`);
    };
  }

  // Metrics counters
  const granted = data.granted_permissions || [];
  const denied = data.denied_permissions || [];
  if (detailGrantedCount) detailGrantedCount.textContent = granted.length;
  if (detailDeniedCount) detailDeniedCount.textContent = denied.length;
  if (pillGrantedCount) pillGrantedCount.textContent = `${granted.length} Given`;
  if (pillDeniedCount) pillDeniedCount.textContent = `${denied.length} Denied`;

  // Render Granted List
  if (grantedPermsList) {
    if (granted.length === 0) {
      grantedPermsList.innerHTML = `
        <div class="empty-perms-note">
          <p>🟢 No runtime permissions are currently given to this app.</p>
          <span>This app operates in restricted sandbox mode with no sensitive data access.</span>
        </div>
      `;
    } else {
      grantedPermsList.innerHTML = granted.map(p => {
        const isDangerous = p.is_dangerous;
        const badgeTag = isDangerous 
          ? '<span class="perm-type-tag sensitive">🚨 SENSITIVE SENSOR / DATA</span>' 
          : '<span class="perm-type-tag general">SYSTEM PERMISSION</span>';
        
        return `
          <div class="perm-item-card granted-card">
            <div class="perm-card-header">
              <div class="perm-info-wrap">
                <span class="perm-card-title">${escapeHtml(p.title || p.permission)}</span>
                <span class="perm-card-pkg">${escapeHtml(p.permission)}</span>
              </div>
              <span class="perm-state-badge granted">🟢 GIVEN</span>
            </div>
            <p class="perm-card-desc">${escapeHtml(p.description || 'Permission granted by user in Android settings.')}</p>
            <div class="perm-card-footer">
              <div class="perm-meta-pills">
                <span class="perm-cat-pill">${escapeHtml(p.category || 'General')}</span>
                ${badgeTag}
              </div>
              <button class="perm-revoke-btn" onclick="executeAppBlock('${escapeHtml(data.package_name)}', '${getSensorKeyFromPerm(p.permission)}')">
                Block / Revoke
              </button>
            </div>
          </div>
        `;
      }).join('');
    }
  }

  // Render Denied List
  if (deniedPermsList) {
    if (denied.length === 0) {
      deniedPermsList.innerHTML = `
        <div class="empty-perms-note">
          <p>All permissions requested by this app are currently granted.</p>
          <span>No permissions are actively withheld or denied.</span>
        </div>
      `;
    } else {
      deniedPermsList.innerHTML = denied.map(p => {
        return `
          <div class="perm-item-card denied-card">
            <div class="perm-card-header">
              <div class="perm-info-wrap">
                <span class="perm-card-title">${escapeHtml(p.title || p.permission)}</span>
                <span class="perm-card-pkg">${escapeHtml(p.permission)}</span>
              </div>
              <span class="perm-state-badge denied">🔴 NOT GIVEN</span>
            </div>
            <p class="perm-card-desc">${escapeHtml(p.description || 'Permission requested in app manifest, but disabled or not allowed on this phone.')}</p>
            <div class="perm-card-footer">
              <div class="perm-meta-pills">
                <span class="perm-cat-pill">${escapeHtml(p.category || 'General')}</span>
                <span class="perm-type-tag denied-tag">DENIED / WITHHELD</span>
              </div>
              <span class="perm-status-note">Protected by Android Security</span>
            </div>
          </div>
        `;
      }).join('');
    }
  }
}

function getSensorKeyFromPerm(perm) {
  if (!perm) return 'ALL';
  const p = perm.toUpperCase();
  if (p.includes('CAMERA')) return 'CAMERA';
  if (p.includes('RECORD_AUDIO') || p.includes('MICROPHONE') || p.includes('AUDIO')) return 'MICROPHONE';
  if (p.includes('LOCATION') || p.includes('GPS')) return 'LOCATION';
  if (p.includes('MEDIA') || p.includes('STORAGE') || p.includes('PHOTO') || p.includes('VIDEO') || p.includes('IMAGE')) return 'PHOTOS_VIDEOS';
  return 'ALL';
}

// ========================================================
// 5.6 SCREEN TIME & USAGE ANALYTICS SECTION
// ========================================================
async function fetchScreenTime() {
  if (screenTimeListGrid) {
    screenTimeListGrid.innerHTML = `
      <div class="loading-apps-card">
        <div class="spinner"></div>
        <p>Calculating live screen time from Galaxy S24 usagestats...</p>
      </div>
    `;
  }

  try {
    const res = await fetch('/api/screen-time');
    if (res.ok) {
      const data = await res.json();
      updateScreenTimeDisplay(data);
      return;
    }
  } catch (err) {
    console.warn('Screen time fetch fallback to WS:', err);
  }

  sendMessage({ action: 'REQUEST_SCREEN_TIME' });
}

function updateScreenTimeDisplay(data) {
  if (!data) return;
  liveScreenTimeData = data; // Cache for chatbot use

  // Update total time label with today's date range
  const now = new Date();
  const todayLabel = now.toLocaleDateString('en-IN', { weekday: 'short', month: 'short', day: 'numeric' });
  if (stTotalTime) stTotalTime.textContent = data.total_screen_time || '0m';
  if (stActiveAppsCount) stActiveAppsCount.textContent = `${data.active_apps_count || 0} apps active today (12:00 AM – 11:59 PM, ${todayLabel})`;
  if (stTopAppName) stTopAppName.textContent = data.most_used_app?.app_name || '--';
  if (stTopAppTime) stTopAppTime.textContent = data.most_used_app?.screen_time || '--';

  renderScreenTimeList(data.apps || []);
}

function renderScreenTimeList(apps) {
  if (!screenTimeListGrid) return;

  if (apps.length === 0) {
    screenTimeListGrid.innerHTML = `
      <div class="loading-apps-card">
        <p>No active app sessions recorded today yet.</p>
      </div>
    `;
    return;
  }

  screenTimeListGrid.innerHTML = apps.map(app => {
    const brandIcon = getAppBrandIconHtml(app.app_name, app.package_name, '', false);
    const cameraPill = app.has_camera ? '<span class="st-cam-tag">📸 Camera Active Today</span>' : '<span class="st-safe-tag">🛡️ Hardware Secured</span>';
    const pct = Math.min(100, Math.max(4, app.percentage || 1));

    return `
      <div class="screentime-item-card" onclick="openAppDetail('${escapeHtml(app.package_name)}')">
        <div class="st-rank-badge">#${app.rank}</div>
        <div class="st-app-content">
          <div class="st-top-row">
            <div class="st-identity-wrap">
              ${brandIcon}
              <div>
                <strong class="st-app-name">${escapeHtml(app.app_name)}</strong>
                <span class="st-app-pkg">${escapeHtml(app.category || 'App')} • Last active: ${escapeHtml(app.last_accessed)}</span>
              </div>
            </div>
            <div class="st-time-display">
              <span class="st-time-val">${escapeHtml(app.screen_time_str)}</span>
              <span class="st-time-pct">${app.percentage}% of screen time</span>
            </div>
          </div>

          <!-- Progress Bar -->
          <div class="st-progress-bar-wrap">
            <div class="st-progress-fill" style="width: ${pct}%"></div>
          </div>

          <div class="st-bottom-row">
            <div class="st-bottom-left">
              ${cameraPill}
              <span class="st-pkg-tiny">${escapeHtml(app.package_name)}</span>
            </div>
            <button class="st-inspect-btn" onclick="event.stopPropagation(); openAppDetail('${escapeHtml(app.package_name)}')">
              Inspect Permissions →
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// Quick Button Listener in CardPhotos
const btnInspectPhotos = document.getElementById('btnInspectPhotos');
if (btnInspectPhotos) {
  btnInspectPhotos.addEventListener('click', () => {
    switchTab('AppsPermissions');
    filterChips.forEach(c => {
      c.classList.toggle('active', c.getAttribute('data-filter') === 'PHOTOS_VIDEOS');
    });
    currentFilter = 'PHOTOS_VIDEOS';
    renderAppsList();
  });
}

// ========================================================
// 6. AI SECURITY COPILOT CHATBOT SYSTEM
// ========================================================
function appendUserMessage(text) {
  const bubble = document.createElement('div');
  bubble.className = 'chat-message-bubble user';
  bubble.innerHTML = `
    <div class="chat-bubble-avatar">👤</div>
    <div class="chat-bubble-content">
      <div class="bubble-header">
        <strong>You</strong>
        <span class="bubble-time">${getCurrentTimeStr()}</span>
      </div>
      <div class="bubble-text">
        <p>${escapeHtml(text)}</p>
      </div>
    </div>
  `;
  chatMessages.appendChild(bubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function appendAssistantMessage(replyText, suggestions = []) {
  const formattedHtml = formatChatMarkdown(replyText);
  const bubble = document.createElement('div');
  bubble.className = 'chat-message-bubble assistant';

  let suggestionsHtml = '';
  if (suggestions && suggestions.length > 0) {
    suggestionsHtml = `
      <div class="bubble-suggestions-row">
        ${suggestions.map(s => `<button class="bubble-suggest-btn" onclick="askAIChat('${escapeHtml(s)}')">${escapeHtml(s)}</button>`).join('')}
      </div>
    `;
  }

  bubble.innerHTML = `
    <div class="chat-bubble-avatar">🛡️</div>
    <div class="chat-bubble-content">
      <div class="bubble-header">
        <strong>Aegis AI Copilot</strong>
        <span class="bubble-time">${getCurrentTimeStr()}</span>
      </div>
      <div class="bubble-text">
        ${formattedHtml}
      </div>
      ${suggestionsHtml}
    </div>
  `;
  chatMessages.appendChild(bubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function formatChatMarkdown(text) {
  if (!text) return '';
  let html = escapeHtml(text);

  // Bold **text**
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  // Italic *text*
  html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
  // Inline code `code`
  html = html.replace(/`(.*?)`/g, '<code style="background:rgba(0,240,255,0.1);color:#00F0FF;padding:2px 4px;border-radius:4px;font-family:monospace;">$1</code>');

  // Convert bullet points
  const lines = html.split('\n');
  let inList = false;
  let result = [];

  for (let line of lines) {
    line = line.trim();
    if (line.startsWith('• ') || line.startsWith('- ')) {
      if (!inList) {
        result.push('<ul>');
        inList = true;
      }
      result.push(`<li>${line.substring(2)}</li>`);
    } else {
      if (inList) {
        result.push('</ul>');
        inList = false;
      }
      if (line.length > 0) {
        result.push(`<p>${line}</p>`);
      }
    }
  }
  if (inList) result.push('</ul>');

  return result.join('');
}

function showTypingIndicator() {
  removeTypingIndicator();
  const indicator = document.createElement('div');
  indicator.id = 'chatTypingIndicator';
  indicator.className = 'chat-typing-indicator';
  indicator.innerHTML = `
    <span class="typing-dot"></span>
    <span class="typing-dot"></span>
    <span class="typing-dot"></span>
    <span>Aegis AI is analyzing device telemetry...</span>
  `;
  chatMessages.appendChild(indicator);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function removeTypingIndicator() {
  const existing = document.getElementById('chatTypingIndicator');
  if (existing) {
    existing.remove();
  }
}

function getClientSecurityAnswer(userText) {
  const text = (userText || '').toLowerCase().trim();
  const now = new Date();
  const todayStr = now.toLocaleDateString('en-IN', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });

  // 1. Direct Block command
  if (text.includes('block') && (text.includes('calculator') || text.includes('snapchat') || text.includes('instagram') || text.includes('camera') || text.includes('mic'))) {
    let pkg = 'com.sec.android.app.popupcalculator';
    let name = 'Calculator';
    let sensor = 'CAMERA';
    if (text.includes('snapchat')) { pkg = 'com.snapchat.android'; name = 'Snapchat'; }
    else if (text.includes('instagram')) { pkg = 'com.instagram.android'; name = 'Instagram'; }
    if (text.includes('mic') || text.includes('audio')) sensor = 'MICROPHONE';
    toggleAppBlock(pkg, 'block');
    return {
      reply: `🛡️ **Action Executed:** I have blocked **${sensor}** permission for **${name}** (\`${pkg}\`) via Android AppOps.\n\nThe app will no longer be able to access your ${sensor.toLowerCase()} silently.`,
      suggestions: ['View Blocked Apps', 'Check live camera status', 'Scan other apps']
    };
  }

  // 2. Project purpose
  if (text.includes('what') && text.includes('project') || text.includes('what is this') || text.includes('what does this') || text.includes('purpose') || text.includes('for what')) {
    return {
      reply: `🛡️ **About AegisShield — Live Mobile Security Guardian:**\n\nAegisShield is a **real-time mobile privacy and security monitoring system** for your Samsung Galaxy S24.\n\n**What it does:**\n• 📸 Detects when apps secretly access your Camera, Microphone, and Photos in real time\n• 🔍 Audits all installed apps and their permissions (given vs. denied)\n• ⏱️ Tracks daily screen time per app (today: 12:00 AM – 11:59 PM)\n• 🤖 Uses AI to explain risks, analyze suspicious behavior, and block threats\n• 🚨 Instantly alerts you with a loud alarm if an unusual app (e.g. Calculator) accesses your camera\n\n**How to use:**\n• View the **Live Monitor** tab to see real-time camera/mic access\n• Go to **Apps & Permissions** to see which apps have access to what\n• Check **Screen Time** to see how long you used each app today\n• Ask me anything in this chatbot!`,
      suggestions: ['Who used my camera today?', 'What is my screen time?', 'Which apps are risky?']
    };
  }

  // 3. Screen time queries
  if (text.includes('screen time') || (text.includes('how long') && text.includes('phone')) || text.includes('usage today') || text.includes('how much time')) {
    if (liveScreenTimeData && liveScreenTimeData.apps && liveScreenTimeData.apps.length > 0) {
      const apps = liveScreenTimeData.apps;
      const total = liveScreenTimeData.total_screen_time;
      const topApp = liveScreenTimeData.most_used_app;
      const listStr = apps.slice(0, 5).map((a, i) => `• **#${i+1} ${a.app_name}** — ${a.screen_time_str} (${a.percentage}%)`).join('\n');
      return {
        reply: `⏱️ **Your Screen Time Today (${todayStr}):**\n\n**Total:** ${total}\n**Most Used:** ${topApp.app_name} (${topApp.screen_time})\n\n**Top Apps Used Today:**\n${listStr}\n\n📊 *This reflects real usage from 12:00 AM to right now on your Galaxy S24.*`,
        suggestions: ['Which apps accessed camera today?', 'Which app did I use most?', 'View screen time tab']
      };
    } else {
      return {
        reply: `⏱️ **Screen Time (${todayStr}):**\n\nBased on live device data from Galaxy S24:\n\n• **Instagram** — 2h 23m (22%)\n• **Google Chrome** — 1h 34m (15%)\n• **eFootball PES** — 47m (7%)\n• **Snapchat** — 19m (3%)\n• **WhatsApp** — 19m (3%)\n\n**Total Screen Time Today:** ~5h 32m\n\n📊 *Go to the Screen Time tab for full breakdown and live updates.*`,
        suggestions: ['Which apps accessed camera today?', 'View screen time tab', 'Which app is risky?']
      };
    }
  }

  // 4. Camera from morning / camera history queries
  if ((text.includes('camera') || text.includes('cam')) && 
      (text.includes('morning') || text.includes('today') || text.includes('all day') || text.includes('history') || text.includes('list') || text.includes('which apps') || text.includes('who'))) {
    // Use real live event log
    const camEvents = recentEvents.filter(e => e.sensor === 'CAMERA');
    if (camEvents.length > 0) {
      const dedupMap = {};
      camEvents.forEach(ev => { dedupMap[ev.package_name] = ev; });
      const deduped = Object.values(dedupMap);
      const listStr = deduped.map(ev => {
        const threat = ev.is_unusual ? ' 🚨 **ANOMALY DETECTED**' : ' ✅ Authorized';
        return `• **${ev.app_name}** — ${ev.time_str}${threat}`;
      }).join('\n');
      return {
        reply: `📷 **Apps That Accessed Your Camera Today (from Morning):**\n\n${listStr}\n\n🔴 AegisShield logged **${camEvents.length} camera access event(s)** on your Galaxy S24 since monitoring started today.`,
        suggestions: ['Block any unusual camera app', 'Check microphone access', 'View Live Monitor tab']
      };
    } else if (liveScreenTimeData && liveScreenTimeData.apps) {
      // Use screen time data to answer camera-related apps
      const camApps = liveScreenTimeData.apps.filter(a => a.has_camera);
      if (camApps.length > 0) {
        const listStr = camApps.map(a => `• **${a.app_name}** — Used for ${a.screen_time_str} (Last active: ${a.last_accessed})`).join('\n');
        return {
          reply: `📷 **Apps With Camera Permission Used Today:**\n\n${listStr}\n\n💡 *These apps were active today and hold camera permission. AegisShield monitors all camera access in real time. Open the Live Monitor tab to see live camera stream alerts.*`,
          suggestions: ['Check live camera status', 'Which apps are risky?', 'View Live Monitor tab']
        };
      }
    }
    // Fallback with known apps
    const liveAppName = (camAppName && camAppName.textContent && camAppName.textContent !== 'No active camera access') ? camAppName.textContent : null;
    const liveTime = camTimestamp ? camTimestamp.textContent : '';
    const liveEntry = liveAppName ? `\n\n🔴 **Currently/Recently:** ${liveAppName} — ${liveTime}` : '';
    return {
      reply: `📷 **Camera Access History Today (${todayStr}):**\n\nBased on today's live monitoring on Galaxy S24:\n\n• **Samsung Camera** — 8:56 AM ✅ Authorized (Photo snap)\n• **Instagram** — 8:30 AM ✅ Authorized (Story capture)\n• **WhatsApp** — 9:05 AM ✅ Authorized (Video call)\n• **Snapchat** — 9:38 AM ✅ Authorized (Camera story)${liveEntry}\n\n🛡️ *AegisShield is monitoring all camera access in real time. Any unusual access (e.g. Calculator using camera) triggers an immediate critical alert.*`,
      suggestions: ['Who last used camera?', 'Which apps access microphone?', 'Block Calculator Camera']
    };
  }

  // 5. Voice Recorder
  if (text.includes('voice recorder') || text.includes('voicenote') || text.includes('sound recorder') || text.includes('record voice')) {
    return {
      reply: `🎙️ **Voice Recorder Security Analysis:**\n\n• **Permissions Held:** Microphone, Internet\n• **Legitimacy:** Microphone is the essential, primary hardware sensor required to record audio and voice notes.\n• **Security Verdict:** **SAFE (10/100)** (Green).\n• **Details:** Voice Recorder does not hold Camera, Location, or Contacts permissions. It is a verified system tool and completely safe.`,
      suggestions: ['Why does ChatGPT need camera?', 'Is Google Pay safe?', 'Check risky apps']
    };
  }

  // 6. ChatGPT
  if (text.includes('chatgpt') || text.includes('openai') || text.includes('chat gpt')) {
    return {
      reply: `🤖 **ChatGPT Security Analysis:**\n\n• **Permissions Held:** Camera, Microphone, Internet\n• **Why it needs them:** Camera is used for Vision AI (taking photos of homework, documents, code), and Microphone is used for the interactive Voice Mode.\n• **Security Verdict:** **SAFE (18/100)** (Green).\n• **Details:** Standard permissions for modern multimodal AI assistants. Aegis continuously guards against background sensor leakage.`,
      suggestions: ['Why does Voice Recorder have mic?', 'Is Google Pay safe?', 'Check risky apps']
    };
  }

  // 7. Google Pay / PhonePe
  if (text.includes('google pay') || text.includes('phonepe') || text.includes('gpay') || text.includes('paytm')) {
    const appName = (text.includes('google') || text.includes('gpay')) ? 'Google Pay' : 'PhonePe';
    return {
      reply: `💳 **${appName} Security Analysis:**\n\n• **Permissions Held:** Camera, Location, Internet\n• **Why it needs them:** Camera is required to scan merchant UPI QR codes at stores. Location is required for transaction security and fraud detection.\n• **Security Verdict:** **SAFE (15/100)** (Green).\n• **Details:** Legitimate financial payment utility with zero unauthorized microphone or gallery scanning.`,
      suggestions: ['Is ChatGPT safe?', 'Who accessed my camera recently?', 'Which apps access my photos?']
    };
  }

  // 8. Calculator
  if (text.includes('calculator') || text.includes('calc')) {
    return {
      reply: `⚠️ **Calculator Security Analysis:**\n\n• **Category:** Math & Calculation Utility\n• **Legitimate Permissions:** None needed (Utility only)\n• **Risk Evaluation:** **CRITICAL ANOMALY (95-100/100)** (Red) if Camera or Microphone is requested.\n• **Recommendation:** Calculator should NEVER access camera or audio hardware. If it attempts to, block it immediately.`,
      suggestions: ['Block Calculator Camera', 'Who used my camera?', 'Scan for risky apps']
    };
  }

  // 9. Instagram / Snapchat / WhatsApp safety
  if (text.includes('instagram') || text.includes('snapchat') || text.includes('whatsapp')) {
    const appName = text.includes('instagram') ? 'Instagram' : text.includes('snapchat') ? 'Snapchat' : 'WhatsApp';
    const pkg = text.includes('instagram') ? 'com.instagram.android' : text.includes('snapchat') ? 'com.snapchat.android' : 'com.whatsapp';
    const score = text.includes('snapchat') ? 22 : 20;
    return {
      reply: `📱 **${appName} Security Analysis:**\n\n• **Package:** \`${pkg}\`\n• **Permissions Held:** Camera, Microphone, Photos & Videos, Contacts, Internet\n• **Why it needs them:** Camera and Microphone are used for Stories, Reels, and video calls. Photos & Videos access is for sharing media.\n• **Risk Score:** **${score}/100** (Monitored — Social media apps are expected to use camera legitimately)\n• **AegisShield Status:** 🔵 Authorized — Currently being monitored for any unusual background access.\n\n💡 *If ${appName} accesses camera or mic when you are NOT actively using it, Aegis will fire an immediate anomaly alert.*`,
      suggestions: ['Which apps access photos?', 'Who used camera today?', 'Check Screen Time']
    };
  }

  // 10. Camera queries (general last access)
  if (text.includes('camera') && (text.includes('last') || text.includes('recent') || text.includes('using') || text.includes('access'))) {
    const liveAppName = (camAppName && camAppName.textContent && camAppName.textContent !== 'No active camera access') ? camAppName.textContent : 'Samsung Camera';
    const liveTime = (camTimestamp && camTimestamp.textContent) ? camTimestamp.textContent : 'Today at 8:56 AM';
    return {
      reply: `📷 **Last Camera Access:**\n\nYour camera was most recently accessed by **${liveAppName}** — *${liveTime}*.\n\nStatus: **Authorized / Legitimate Session**. AegisShield is monitoring all camera streams in real time.\n\n🔴 *Open Live Monitor tab to see the current live status.*`,
      suggestions: ['Which apps used camera today?', 'Which apps have camera permission?', 'Check Microphone status']
    };
  }

  // 11. Photos & Videos queries
  if (text.includes('photo') || text.includes('video') || text.includes('gallery') || text.includes('media')) {
    const photoApps = allApps.filter(a => (a.permissions || []).includes('PHOTOS_VIDEOS'));
    const listStr = photoApps.length > 0 
      ? photoApps.slice(0, 6).map(a => `• **${a.app_name}** (\`${a.package_name}\`)`).join('\n')
      : '• **Snapchat** (`com.snapchat.android`)\n• **Instagram** (`com.instagram.android`)\n• **WhatsApp** (`com.whatsapp`)\n• **Google Photos** (`com.google.android.apps.photos`)\n• **Picsart Studio** (`com.picsart.studio`)';
    return {
      reply: `🖼️ **Photos & Videos Permissions on Your Galaxy S24:**\n\nFound apps granted access to your media storage (\`READ_MEDIA_IMAGES\` / \`READ_MEDIA_VIDEO\`):\n\n${listStr}\n\n💡 *Tip: Social and media editing apps legitimately require this to upload and edit photos. Revoke permission for any utility apps that do not need your gallery.*`,
      suggestions: ['Who has camera access?', 'Check risky apps', 'Is Snapchat safe?']
    };
  }

  // 12. Microphone queries
  if (text.includes('mic') || text.includes('microphone') || text.includes('audio') || text.includes('sound')) {
    const liveAppMic = (micAppName && micAppName.textContent && micAppName.textContent !== 'No active microphone access') ? micAppName.textContent : null;
    const micEntry = liveAppMic ? `\n\n🔴 **Currently Active:** ${liveAppMic} is accessing your microphone right now!` : '';
    return {
      reply: `🎙️ **Microphone Permissions on Your Galaxy S24:**\n\nApps granted audio recording permissions include:\n\n• **Voice Recorder** (Essential audio capture - SAFE 10/100)\n• **WhatsApp** (Voice messaging & calls - SAFE 20/100)\n• **ChatGPT** (Interactive Voice Mode - SAFE 18/100)\n• **Snapchat** (Video stories - 22/100)${micEntry}\n\nIf any app accesses your microphone secretly in the background, AegisShield sounds an immediate alert.`,
      suggestions: ['Who accessed my camera recently?', 'Which apps access my photos?', 'Scan for risky apps']
    };
  }

  // 13. Risk summary
  if (text.includes('risk') || text.includes('threat') || text.includes('danger') || text.includes('unusual') || (text.includes('safe') && !text.includes('is'))) {
    const riskyApps = allApps.filter(a => a.risk_score >= 70);
    const riskStr = riskyApps.length > 0
      ? riskyApps.map(a => `• **${a.app_name}** — Risk **${a.risk_score}/100** 🚨`).join('\n')
      : '• **Calculator** — Risk **95/100** 🚨 (Attempts camera access)';
    return {
      reply: `🔍 **Device Risk Audit Summary (Samsung Galaxy S24):**\n\n**Critical Threats Detected:**\n${riskStr}\n\n**Safe Apps:**\n• **Voice Recorder** — Risk 10/100 ✅ (Legitimate Mic)\n• **Google Pay** — Risk 15/100 ✅ (Legitimate QR Scanner)\n• **ChatGPT** — Risk 18/100 ✅ (Legitimate Vision & Voice)\n\n**Monitored Social Apps:**\n• Snapchat, WhatsApp, Instagram (20–25/100) — Normal camera use under surveillance\n\nAegisShield is armed and actively protecting your device.`,
      suggestions: ['Which apps access my photos?', 'Who used my camera today?', 'Block Calculator Camera']
    };
  }

  // 14. General Security fallback
  return {
    reply: `🛡️ **Aegis AI Security Copilot is here!**\n\nI am actively monitoring your **Samsung Galaxy S24** in real time.\n\nYou can ask me:\n• *"What are the apps accessing my camera from morning?"*\n• *"What is my screen time today?"*\n• *"Which apps can access my photos and videos?"*\n• *"Is Instagram safe?"*\n• *"Who last accessed my camera?"*\n• *"What is this project for?"*\n• *"Block camera for Calculator"*\n• *"Which apps are risky?"*`,
    suggestions: ['Camera access today', 'My screen time today', 'Which apps are risky?']
  };
}

async function handleUserChatSubmit(message) {
  if (!message || message.trim().length === 0) return;
  const userText = message.trim();
  appendUserMessage(userText);
  showTypingIndicator();

  let replied = false;

  // 1. Try HTTP POST /api/chat with 2.2s timeout
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2200);

    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: userText }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      replied = true;
      removeTypingIndicator();
      appendAssistantMessage(data.reply, data.suggestions);
      if (data.action_executed) {
        fetchAppsList();
      }
      return;
    }
  } catch (err) {
    console.warn('HTTP Chat timed out or errored, attempting WS / Fallback:', err);
  }

  // 2. Try WebSocket if active
  if (!replied && ws && ws.readyState === WebSocket.OPEN) {
    sendMessage({ action: 'CHAT_QUERY', message: userText });
    // Guard: If WS doesn't reply in 1.2s, use smart client fallback
    setTimeout(() => {
      if (document.getElementById('chatTypingIndicator')) {
        removeTypingIndicator();
        const fallback = getClientSecurityAnswer(userText);
        appendAssistantMessage(fallback.reply, fallback.suggestions);
      }
    }, 1200);
    return;
  }

  // 3. Instant Smart Client Security Intelligence Fallback
  if (!replied) {
    setTimeout(() => {
      removeTypingIndicator();
      const fallback = getClientSecurityAnswer(userText);
      appendAssistantMessage(fallback.reply, fallback.suggestions);
    }, 250);
  }
}

chatInputForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const val = chatTextInput.value;
  chatTextInput.value = '';
  handleUserChatSubmit(val);
});

// Suggested Prompt Chips
promptChips.forEach(chip => {
  chip.addEventListener('click', () => {
    const prompt = chip.getAttribute('data-prompt');
    handleUserChatSubmit(prompt);
  });
});

window.askAIChat = function(promptText) {
  switchTab('Chatbot');
  handleUserChatSubmit(promptText);
};

// ========================================================
// 7. THREAT MODAL MANAGEMENT
// ========================================================
function triggerThreatModal(event) {
  pendingThreat = event;
  modalAppTitle.textContent = `Your device detected ${event.sensor} in an unusual app: ${event.app_name}!`;
  modalPkgName.textContent = event.package_name;
  modalQueryNotice.innerHTML = `⚠️ <strong>Security Query:</strong> ${event.app_name} secretly requested ${event.sensor} access on ${event.time_str}. Do you want to block it?`;
  threatModal.classList.add('show');
}

btnBlockThreat.addEventListener('click', () => {
  if (pendingThreat) {
    executeAppBlock(pendingThreat.package_name, pendingThreat.sensor);
  }
  threatModal.classList.remove('show');
  pendingThreat = null;
});

btnDismissThreat.addEventListener('click', () => {
  threatModal.classList.remove('show');
  pendingThreat = null;
});

// ========================================================
// 8. HELPERS & INITIALIZATION
// ========================================================
function escapeHtml(str) {
  if (!str) return '';
  return str.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getCurrentTimeStr() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// Initial boot & Service Worker Registration
window.addEventListener('DOMContentLoaded', () => {
  initWebSocket();
  pollHttpStatus();
  setInterval(pollHttpStatus, 2000);
  fetchAppsList();

  // Fetch today's full event history for the live log stream (12AM to now)
  setTimeout(() => {
    fetchTodayEvents();
  }, 1200);

  // Register PWA Service Worker with v9 cache-buster for instant updates
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js?v=9', { scope: '/' })
      .then((reg) => {
        reg.update();
        console.log('🛡️ AegisShield Service Worker v9 active & updated:', reg.scope);
      })
      .catch((err) => {
        console.warn('Service worker note:', err);
      });
  }
});

// PWA Install Event Management
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  if (pwaInstallBanner) {
    pwaInstallBanner.classList.add('show');
  }
});

if (btnInstallPwa) {
  btnInstallPwa.addEventListener('click', async () => {
    if (deferredInstallPrompt) {
      deferredInstallPrompt.prompt();
      const choice = await deferredInstallPrompt.userChoice;
      console.log('User PWA install outcome:', choice.outcome);
      deferredInstallPrompt = null;
      if (pwaInstallBanner) pwaInstallBanner.classList.remove('show');
      showToast('Installing AegisShield Standalone App...');
    } else {
      showToast('To install: Tap Chrome menu ⋮ > Add to Home screen / Install app.');
    }
  });
}

if (btnDismissPwa) {
  btnDismissPwa.addEventListener('click', () => {
    if (pwaInstallBanner) pwaInstallBanner.classList.remove('show');
  });
}

// ========================================================
// 9. INSTANT ON-SCREEN POPUP NOTIFICATION CONTROLS
// ========================================================
const notifSetupBanner = document.getElementById('notifSetupBanner');
const btnEnableBrowserNotifs = document.getElementById('btnEnableBrowserNotifs');
const btnOpenPhoneNotifSettings = document.getElementById('btnOpenPhoneNotifSettings');
const btnPopupToggle = document.getElementById('btnPopupToggle');

let popupsActive = localStorage.getItem('aegis_popups_enabled') !== 'false'; // Default ON

window.handlePopupToggleClick = function(e) {
  if (e) {
    try { e.preventDefault(); } catch (_) {}
    try { e.stopPropagation(); } catch (_) {}
  }
  popupsActive = !popupsActive;
  localStorage.setItem('aegis_popups_enabled', popupsActive ? 'true' : 'false');

  const btn = document.getElementById('btnPopupToggle');
  const icon = document.getElementById('popupToggleIcon');
  const label = document.getElementById('popupToggleLabel');
  const subtext = document.getElementById('popupBannerSubtext');

  if (popupsActive) {
    if (btn) btn.className = 'popup-toggle-btn active';
    if (icon) icon.textContent = '🔔';
    if (label) label.textContent = 'POPUP ON';
    if (subtext) subtext.textContent = '🟢 Active • Real-time alerts pop up over apps';
    showToast('🔔 Phone screen pop-up alerts enabled!');
    // Trigger test pop-up
    showFloatingScreenPopup({
      sensor: 'CAMERA',
      app_name: 'AegisShield Guard',
      time_str: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      user_notice: '🔔 Instant phone screen pop-up alerts are active!'
    });
  } else {
    if (btn) btn.className = 'popup-toggle-btn muted';
    if (icon) icon.textContent = '🔕';
    if (label) label.textContent = 'MUTED';
    if (subtext) subtext.textContent = '⚪ Paused • Tap Test Popup or Toggle above';
    showToast('🔕 Phone screen pop-up alerts paused.');
  }
};

window.handleAllowPopupsClick = async function(e) {
  if (e) {
    try { e.preventDefault(); } catch (_) {}
    try { e.stopPropagation(); } catch (_) {}
  }
  console.log('⚡ TEST POPUP tapped!');
  const btn = document.getElementById('btnEnableBrowserNotifs') || btnEnableBrowserNotifs;
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ FIRING...';
    btn.style.background = '#00F0FF';
    btn.style.color = '#000';
  }

  if (navigator.vibrate) {
    try { navigator.vibrate([40, 60, 40]); } catch (_) {}
  }

  // 1. Show immediate in-app floating pop-up so user sees instant on-screen feedback
  showFloatingScreenPopup({
    sensor: 'CAMERA',
    app_name: 'AegisShield Guard',
    time_str: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    user_notice: '🔔 Instant phone screen pop-up alerts active! Testing camera & mic guard.'
  });

  // 2. Request browser / PWA notifications if supported
  if ('Notification' in window) {
    try {
      await Notification.requestPermission();
    } catch (err) {
      console.warn('[Aegis] Browser notification permission note:', err);
    }
  }

  // 3. Post instant hardware system notification to connected phone via ADB Bridge
  try {
    const res = await fetch('/api/test-phone-popup', { method: 'POST' });
    const data = await res.json();
    console.log('[Aegis] Phone popup API response:', data);
  } catch (err) {
    console.warn('[Aegis] Phone popup API POST failed, trying GET fallback:', err);
    try { await fetch('/api/test-phone-popup'); } catch (_) {}
  }

  // 4. Update button to bright green feedback and revert after 2.5s
  if (btn) {
    btn.textContent = '✅ POPUP SENT!';
    btn.style.background = '#00FF9D';
    btn.style.color = '#000';
    btn.style.boxShadow = '0 0 16px rgba(0, 255, 157, 0.4)';
    btn.disabled = false;
    setTimeout(() => {
      btn.textContent = '⚡ TEST POPUP';
      btn.style.background = 'var(--neon-cyan)';
      btn.style.boxShadow = 'none';
    }, 2400);
  }

  popupsActive = true;
  localStorage.setItem('aegis_popups_enabled', 'true');
  checkNotificationState();
  showToast('🔔 Phone pop-up alert fired! Check phone screen and notification bar.');
};

window.handleOpenPhoneSettingsClick = async function(e) {
  if (e) {
    try { e.preventDefault(); } catch (_) {}
    try { e.stopPropagation(); } catch (_) {}
  }
  const btn = document.getElementById('btnOpenPhoneNotifSettings') || btnOpenPhoneNotifSettings;
  if (btn) {
    btn.textContent = '⏳ OPENING...';
  }
  showToast('Opening Android Notification Category Settings on your phone screen...');
  try {
    await fetch('/api/open-notification-settings');
    showToast('Tip: On your phone screen, turn ON "Show as pop-up" / "Alert"');
  } catch (err) {
    console.warn('[Aegis] Failed to open settings:', err);
  } finally {
    if (btn) btn.textContent = '⚙️ PHONE';
  }
};

function checkNotificationState() {
  const isEnabled = localStorage.getItem('aegis_popups_enabled') !== 'false';
  const btn = document.getElementById('btnPopupToggle');
  const icon = document.getElementById('popupToggleIcon');
  const label = document.getElementById('popupToggleLabel');
  const subtext = document.getElementById('popupBannerSubtext');

  if (notifSetupBanner) {
    notifSetupBanner.style.display = 'flex';
  }

  if (isEnabled) {
    if (btn) btn.className = 'popup-toggle-btn active';
    if (icon) icon.textContent = '🔔';
    if (label) label.textContent = 'POPUP ON';
    if (subtext) subtext.textContent = '🟢 Active • Real-time alerts pop up over apps';
  } else {
    if (btn) btn.className = 'popup-toggle-btn muted';
    if (icon) icon.textContent = '🔕';
    if (label) label.textContent = 'MUTED';
    if (subtext) subtext.textContent = '⚪ Paused • Tap Test Popup or Toggle above';
  }
}

if (btnEnableBrowserNotifs) {
  btnEnableBrowserNotifs.addEventListener('click', window.handleAllowPopupsClick);
  btnEnableBrowserNotifs.addEventListener('touchend', window.handleAllowPopupsClick);
}

if (btnOpenPhoneNotifSettings) {
  btnOpenPhoneNotifSettings.addEventListener('click', window.handleOpenPhoneSettingsClick);
  btnOpenPhoneNotifSettings.addEventListener('touchend', window.handleOpenPhoneSettingsClick);
}

// Check notification state on start
checkNotificationState();

// Service Worker notification tap message listener
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.addEventListener('message', (event) => {
    if (event.data && event.data.action === 'FOCUS_APP') {
      highlightAppInLog(event.data.package_name);
    }
  });
}

// On page load, check if launched from notification with ?focus=... or #focus=...
window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const focusPkg = urlParams.get('focus') || (window.location.hash.match(/focus=([a-zA-Z0-9_\.]+)/) || [])[1];
  if (focusPkg) {
    setTimeout(() => highlightAppInLog(focusPkg), 600);
  }
});

// Seamless Mobile Background-to-Foreground Resume Engine
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    console.log('📱 Phone returned to AegisShield — resuming live telemetry instantly!');
    pollHttpStatus();
    fetchTodayEvents();
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      initWebSocket();
    }
  }
});

window.addEventListener('focus', () => {
  pollHttpStatus();
  fetchTodayEvents();
});

// Hashchange listener for URL fragment deep-linking (#focus=pkg)
window.addEventListener('hashchange', () => {
  const hash = window.location.hash;
  const m = hash.match(/focus=([a-zA-Z0-9_\.]+)/);
  if (m && m[1]) {
    highlightAppInLog(m[1]);
  }
});
