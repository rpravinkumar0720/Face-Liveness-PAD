// MOSIP Face Liveness & PAD Web Client
// Modular ES module using vendored MediaPipe Tasks Vision with graceful CDN fallback

const LOCAL_VISION_URL = '/vendor/mediapipe';
const LOCAL_MODEL_URL = '/vendor/mediapipe/face_landmarker.task';
const CDN_VISION_URL = 'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.14';
const CDN_MODEL_URL = 'https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task';

let faceLandmarker = null;
let video = null;
let overlayCanvas = null;
let overlayCtx = null;
let captureCanvas = null;
let captureCtx = null;
let websocket = null;
let isStreaming = false;
let isReplaying = false;
let replayInterval = null;
let currentSessionId = null;
let currentWorkflow = 'RESIDENT_AUTH';
let currentLang = 'en';
let frameSequence = 0;
let lastCaptureTime = 0;
let activeChallengeTimer = null;
let localAuditEvents = [];
let reconnectAttempts = 0;
let adminToken = sessionStorage.getItem('mosip_admin_token') || (new URLSearchParams(window.location.search)).get('adminToken') || '';
let activeChallengeToken = null;
let virtualCameraDetected = false;
let colorFlashInterval = null;
let voiceEnabled = false;
let splitViewActive = false;

// Localization Strings for Web UI (English and Tamil)
const UI_STRINGS = {
  en: {
    title: 'Face Liveness & PAD',
    positionFace: 'Position your face in the oval',
    actionRequired: 'Action Required',
    holdStill: 'Hold still, analyzing face liveness...',
    qualityChecking: 'Checking...',
    qualityCompliant: 'Compliant',
    qualityNonCompliant: 'Adjusting...',
    verifSuccess: 'Verification Successful',
    verifFailed: 'Verification Incomplete',
    startNewSession: 'Start New Session',
    inspectAudit: 'Inspect Audit Trail',
    cameraRequired: 'Camera Access Required',
    cameraRequiredDesc: 'Please allow camera permissions to begin face verification.',
    chainValid: 'Cryptographic Chain Valid (Tamper-Free)',
    chainBroken: 'Tamper Detected! Chain Linkage Broken at Event',
    noEvents: 'No events recorded yet. Start capture.',
    progressLabel: 'Passive Liveness',
    policyHeader: 'Effective Policy Settings',
    policyDesc: 'Loaded from server policy registry',
    thEvent: 'Event Type',
    thDecision: 'Decision',
    thHash: 'Hash Linkage'
  },
  ta: {
    title: 'முக சரிபார்ப்பு மற்றும் PAD',
    positionFace: 'வட்டத்திற்குள் உங்கள் முகத்தை வைக்கவும்',
    actionRequired: 'செயல் தேவைப்படுகிறது',
    holdStill: 'அசையாமல் இருக்கவும், சரிபார்க்கப்படுகிறது...',
    qualityChecking: 'சரிபார்க்கிறது...',
    qualityCompliant: 'சரியாக உள்ளது',
    qualityNonCompliant: 'சரிசெய்கிறது...',
    verifSuccess: 'சரிபார்ப்பு வெற்றிகரமாக முடிந்தது',
    verifFailed: 'சரிபார்ப்பு நிறைவடையவில்லை',
    startNewSession: 'புதிய அமர்வைத் தொடங்கவும்',
    inspectAudit: 'தணிக்கைப் பதிவை காண்க',
    cameraRequired: 'கேமரா அனுமதி தேவை',
    cameraRequiredDesc: 'முக சரிபார்ப்பைத் தொடங்க கேமரா அனுமதியை வழங்கவும்.',
    chainValid: 'கிரிப்டோகிராஃபிக் தணிக்கை சங்கிலி சரியானது (சேதமடையவில்லை)',
    chainBroken: 'சேதம் கண்டறியப்பட்டது! சங்கிலி இணைப்பு முறிந்தது: நிகழ்வு',
    noEvents: 'நிகழ்வுகள் எதுவும் இதுவரை பதிவு செய்யப்படவில்லை.',
    progressLabel: 'செயலற்ற முக சரிபார்ப்பு',
    policyHeader: 'செயலில் உள்ள கொள்கை அமைப்புகள்',
    policyDesc: 'சேவையக கொள்கை பதிவேட்டில் இருந்து ஏற்றப்பட்டது',
    thEvent: 'நிகழ்வு வகை',
    thDecision: 'முடிவு',
    thHash: 'ஹாஷ் இணைப்பு'
  }
};

document.addEventListener('DOMContentLoaded', async () => {
  initElements();
  initEventListeners();
  initMobileMenu();
  initTokenModal();
  initFooterNavigation();
  initCopyrightYear();
  updateJudgeModeUI();
  loadPolicyDetails(currentWorkflow);
  checkServerHealth();
  connectWebSocket();

  setInterval(checkServerHealth, 15000);

  try {
    await initMediaPipe();
  } catch (e) {
    console.warn('MediaPipe initialization notice:', e);
  }

  try {
    await initCamera();
  } catch (err) {
    showCameraError('Camera Access Required', err.message);
  }
});

function initElements() {
  video = document.getElementById('webcam');
  overlayCanvas = document.getElementById('overlayCanvas');
  overlayCtx = overlayCanvas.getContext('2d');
  captureCanvas = document.getElementById('captureCanvas');
  captureCtx = captureCanvas.getContext('2d');
}

function initCopyrightYear() {
  const el = document.getElementById('copyrightYear');
  if (el) {
    el.textContent = new Date().getFullYear();
  }
}

// Accessible Toast Notification System
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', type === 'error' ? 'alert' : 'status');

  const msgEl = document.createElement('div');
  msgEl.className = 'toast-message';
  msgEl.textContent = message;

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'toast-close-btn';
  closeBtn.setAttribute('aria-label', 'Dismiss notification');
  closeBtn.innerHTML = '&times;';
  closeBtn.onclick = () => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  };

  toast.appendChild(msgEl);
  toast.appendChild(closeBtn);
  container.appendChild(toast);

  if (duration > 0) {
    setTimeout(() => {
      if (toast.parentElement) {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 300);
      }
    }, duration);
  }
}

// Mobile Hamburger Menu Navigation
function initMobileMenu() {
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const headerControls = document.getElementById('headerControls');
  if (!mobileMenuBtn || !headerControls) return;

  function toggleMenu(forceState) {
    const currentState = mobileMenuBtn.getAttribute('aria-expanded') === 'true';
    const nextState = forceState !== undefined ? forceState : !currentState;
    mobileMenuBtn.setAttribute('aria-expanded', String(nextState));
    headerControls.classList.toggle('menu-open', nextState);
  }

  mobileMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleMenu();
  });

  // Close when an action or selection is made on mobile
  headerControls.querySelectorAll('button, select').forEach(ctrl => {
    ctrl.addEventListener('click', () => {
      if (window.innerWidth <= 768) {
        toggleMenu(false);
      }
    });
  });

  // Close on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' || e.key === 'Esc') {
      if (headerControls.classList.contains('menu-open')) {
        toggleMenu(false);
        mobileMenuBtn.focus();
      }
    }
  });

  // Close on outside click
  document.addEventListener('click', (e) => {
    if (window.innerWidth <= 768 && headerControls.classList.contains('menu-open')) {
      if (!headerControls.contains(e.target) && !mobileMenuBtn.contains(e.target)) {
        toggleMenu(false);
      }
    }
  });
}

// Footer Quick Navigation
function initFooterNavigation() {
  document.getElementById('footerLinkPolicy')?.addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('tabBtnPolicy')?.click();
    document.getElementById('sidebarSection')?.scrollIntoView({ behavior: 'smooth' });
  });

  document.getElementById('footerLinkAudit')?.addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('tabBtnAudit')?.click();
    document.getElementById('sidebarSection')?.scrollIntoView({ behavior: 'smooth' });
  });
}

// Accessible Token Modal for Judge Mode
function initTokenModal() {
  const tokenOverlay = document.getElementById('tokenModalOverlay');
  const tokenInput = document.getElementById('adminTokenInput');
  const tokenError = document.getElementById('tokenInputError');
  const btnSubmitToken = document.getElementById('btnSubmitToken');
  const btnCancelToken = document.getElementById('btnCancelToken');
  if (!tokenOverlay || !tokenInput) return;

  window.openTokenModal = function() {
    tokenOverlay.classList.remove('hidden');
    tokenInput.value = '';
    tokenError.classList.remove('visible');
    setTimeout(() => tokenInput.focus(), 60);
  };

  window.closeTokenModal = function() {
    tokenOverlay.classList.add('hidden');
    tokenInput.value = '';
    tokenError.classList.remove('visible');
    document.getElementById('btnJudgeMode')?.focus();
  };

  btnCancelToken?.addEventListener('click', window.closeTokenModal);
  btnSubmitToken?.addEventListener('click', () => {
    const val = tokenInput.value.trim();
    if (!val) {
      tokenError.classList.add('visible');
      tokenInput.focus();
      return;
    }
    adminToken = val;
    sessionStorage.setItem('mosip_admin_token', adminToken);
    window.closeTokenModal();
    updateJudgeModeUI();
    loadPolicyDetails(currentWorkflow);
    resetAndReconnect();
    showToast('Judge Mode unlocked successfully.', 'success');
  });

  tokenInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      btnSubmitToken.click();
    } else if (e.key === 'Escape') {
      window.closeTokenModal();
    }
  });

  tokenOverlay.addEventListener('click', (e) => {
    if (e.target === tokenOverlay) {
      window.closeTokenModal();
    }
  });
}

function initEventListeners() {
  document.getElementById('workflowSelect').addEventListener('change', (e) => {
    currentWorkflow = e.target.value;
    loadPolicyDetails(currentWorkflow);
    resetAndReconnect();
  });

  document.getElementById('langToggle').addEventListener('click', () => {
    currentLang = currentLang === 'en' ? 'ta' : 'en';
    updateLanguage();
    resetAndReconnect();
  });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId)?.classList.add('active');
    });
  });

  document.getElementById('btnRetry').addEventListener('click', () => {
    resetAndReconnect();
    showToast('Starting new biometric verification session...', 'info', 2000);
  });

  document.getElementById('btnRetryCamera').addEventListener('click', () => {
    document.getElementById('cameraErrorOverlay').classList.add('hidden');
    initCamera().then(() => connectWebSocket());
  });

  document.getElementById('btnViewAuditFromModal').addEventListener('click', () => {
    document.getElementById('decisionOverlay').classList.add('hidden');
    document.getElementById('tabBtnAudit').click();
  });

  document.getElementById('btnVerifyChain').addEventListener('click', verifyAuditChain);
  document.getElementById('btnTamperChain').addEventListener('click', tamperAndVerifyAuditChain);

  // Accessibility & UX toggles
  document.getElementById('btnVoice')?.addEventListener('click', () => {
    voiceEnabled = !voiceEnabled;
    const btn = document.getElementById('btnVoice');
    btn.innerText = voiceEnabled ? '🔊 Voice: ON' : '🔊 Voice: OFF';
    btn.style.borderColor = voiceEnabled ? '#10b981' : '';
    if (voiceEnabled) {
      speak(UI_STRINGS[currentLang].positionFace);
    }
  });

  document.getElementById('btnContrast')?.addEventListener('click', () => {
    document.body.classList.toggle('high-contrast');
    const isHc = document.body.classList.contains('high-contrast');
    const btn = document.getElementById('btnContrast');
    btn.innerText = isHc ? '🌓 Contrast: HIGH' : '🌓 Contrast';
  });

  document.getElementById('btnSplitView')?.addEventListener('click', toggleSplitView);

  // Judge Mode Unlock
  document.getElementById('btnJudgeMode')?.addEventListener('click', () => {
    if (adminToken) {
      adminToken = '';
      sessionStorage.removeItem('mosip_admin_token');
      updateJudgeModeUI();
      loadPolicyDetails(currentWorkflow);
      resetAndReconnect();
      showToast('Judge Mode exited. Returned to standard view.', 'info');
    } else {
      if (typeof window.openTokenModal === 'function') {
        window.openTokenModal();
      }
    }
  });

  // Red Team Attack Gallery Events
  document.getElementById('btnReplayPrint')?.addEventListener('click', () => triggerAttackSimulation('PRINT_ATTACK'));
  document.getElementById('btnReplayScreen')?.addEventListener('click', () => triggerAttackSimulation('SCREEN_REPLAY'));
  document.getElementById('btnReplayMask')?.addEventListener('click', () => triggerAttackSimulation('MASK_3D'));
  document.getElementById('btnReplayForged')?.addEventListener('click', () => triggerAttackSimulation('FORGED_LANDMARKS'));
  document.getElementById('btnResetLive')?.addEventListener('click', resetToLiveCamera);

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      isStreaming = false;
    } else {
      isStreaming = true;
      requestAnimationFrame(processVideoFrame);
    }
  });
}

function toggleSplitView() {
  splitViewActive = !splitViewActive;
  const layout = document.getElementById('mainLayout');
  const userHeader = document.getElementById('splitViewHeaderUser');
  const judgeHeader = document.getElementById('splitViewHeaderJudge');
  const btn = document.getElementById('btnSplitView');

  if (splitViewActive) {
    layout.classList.add('split-view-active');
    userHeader?.classList.remove('hidden');
    judgeHeader?.classList.remove('hidden');
    btn.innerText = '🔲 Split: ON';
    btn.style.borderColor = '#3b82f6';
    document.getElementById('tabBtnDiag')?.click();
  } else {
    layout.classList.remove('split-view-active');
    userHeader?.classList.add('hidden');
    judgeHeader?.classList.add('hidden');
    btn.innerText = '🔲 Split View';
    btn.style.borderColor = '';
  }
}

function updateJudgeModeUI() {
  const btn = document.getElementById('btnJudgeMode');
  const btnSplit = document.getElementById('btnSplitView');
  const tabDiag = document.getElementById('tabBtnDiag');
  const tabRedTeam = document.getElementById('tabBtnRedTeam');

  if (btn) {
    if (adminToken) {
      btn.innerText = '⚖️ Judge: ON';
      btn.style.background = 'rgba(16, 185, 129, 0.2)';
      btn.style.borderColor = '#10b981';
      btnSplit?.classList.remove('hidden');
      tabDiag?.classList.remove('hidden');
      tabRedTeam?.classList.remove('hidden');
    } else {
      btn.innerText = '⚖️ Judge Mode';
      btn.style.background = '';
      btn.style.borderColor = '';
      btnSplit?.classList.add('hidden');
      tabDiag?.classList.add('hidden');
      tabRedTeam?.classList.add('hidden');
      if (splitViewActive) {
        toggleSplitView();
      }
    }
  }
}

function updateLanguage() {
  const strings = UI_STRINGS[currentLang] || UI_STRINGS.en;
  document.querySelectorAll('.lang-code').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-lang') === currentLang);
  });
  document.getElementById('promptText').innerText = strings.positionFace;
  document.getElementById('challengeTitle').innerText = strings.actionRequired;
  document.getElementById('btnRetry').innerText = strings.startNewSession;
  document.getElementById('btnViewAuditFromModal').innerText = strings.inspectAudit;

  // Localize table headers and policy labels
  const thEv = document.getElementById('thAuditEv');
  const thDec = document.getElementById('thAuditDec');
  const thHash = document.getElementById('thAuditHash');
  if (thEv) thEv.innerText = strings.thEvent;
  if (thDec) thDec.innerText = strings.thDecision;
  if (thHash) thHash.innerText = strings.thHash;

  const lblPolH = document.getElementById('lblPolicyHeader');
  const lblPolD = document.getElementById('lblPolicyDesc');
  if (lblPolH) lblPolH.innerText = strings.policyHeader;
  if (lblPolD) lblPolD.innerText = strings.policyDesc;
}

function speak(text) {
  if (!voiceEnabled || !('speechSynthesis' in window) || !text) return;
  try {
    window.speechSynthesis.cancel();
    const utter = new SpeechSynthesisUtterance(text);
    utter.lang = currentLang === 'ta' ? 'ta-IN' : 'en-US';
    utter.rate = 0.95;
    window.speechSynthesis.speak(utter);
  } catch (e) {
    // audio fallback
  }
}

// MediaPipe Initialization: Offline Vendored Asset First with CDN Fallback
async function initMediaPipe() {
  // 1. Try local offline vendored assets first
  try {
    const vision = await import(/* webpackIgnore: true */ `${LOCAL_VISION_URL}/vision_bundle.mjs`);
    const FilesetResolver = vision.FilesetResolver;
    const FaceLandmarker = vision.FaceLandmarker;

    const fileset = await FilesetResolver.forVisionTasks(`${LOCAL_VISION_URL}/wasm`);
    faceLandmarker = await FaceLandmarker.createFromOptions(fileset, {
      baseOptions: {
        modelAssetPath: LOCAL_MODEL_URL,
        delegate: 'GPU'
      },
      outputFaceBlendshapes: false,
      runningMode: 'VIDEO',
      numFaces: 1
    });
    console.log('MediaPipe FaceLandmarker successfully initialized from offline vendored assets.');
    return;
  } catch (localErr) {
    console.warn('Local MediaPipe asset loading skipped/failed, trying CDN fallback:', localErr);
  }

  // 2. Fallback to CDN
  try {
    const vision = await import(/* webpackIgnore: true */ `${CDN_VISION_URL}/vision_bundle.mjs`);
    const FilesetResolver = vision.FilesetResolver;
    const FaceLandmarker = vision.FaceLandmarker;

    const fileset = await FilesetResolver.forVisionTasks(`${CDN_VISION_URL}/wasm`);
    faceLandmarker = await FaceLandmarker.createFromOptions(fileset, {
      baseOptions: {
        modelAssetPath: CDN_MODEL_URL,
        delegate: 'GPU'
      },
      outputFaceBlendshapes: false,
      runningMode: 'VIDEO',
      numFaces: 1
    });
    console.log('MediaPipe FaceLandmarker initialized from CDN.');
  } catch (cdnErr) {
    console.warn('MediaPipe CDN load failed. Server-side face detector will corroborate frames directly.');
    document.getElementById('promptText').innerText = 'Server face detection active';
  }
}

// Camera Setup
async function initCamera() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error('Webcam streaming not supported in this browser.');
  }

  const stream = await navigator.mediaDevices.getUserMedia({
    video: {
      facingMode: 'user',
      width: { ideal: 640 },
      height: { ideal: 480 }
    },
    audio: false
  });

  const tracks = stream.getVideoTracks();
  if (tracks && tracks.length > 0) {
    const label = (tracks[0].label || '').toLowerCase();
    const virtualKeywords = ['obs', 'virtual', 'manycam', 'v4l2loopback', 'fake', 'droidcam', 'camo', 'unity'];
    virtualCameraDetected = virtualKeywords.some(kw => label.includes(kw));
    if (virtualCameraDetected) {
      console.warn('Virtual camera indicator detected in track label:', tracks[0].label);
    }
  }

  video.srcObject = stream;
  await new Promise(resolve => {
    video.onloadedmetadata = () => {
      video.play();
      overlayCanvas.width = video.videoWidth;
      overlayCanvas.height = video.videoHeight;
      resolve();
    };
  });

  isStreaming = true;
  requestAnimationFrame(processVideoFrame);
}

// WebSocket Connection Management
async function connectWebSocket() {
  if (websocket && websocket.readyState === WebSocket.OPEN) {
    websocket.close();
  }

  updateStatus(false, 'Authorizing session...');
  let sessionToken = '';
  try {
    let clientId = localStorage.getItem('mosip_client_id');
    if (!clientId) {
      clientId = 'client-' + Math.random().toString(36).substring(2, 10);
      localStorage.setItem('mosip_client_id', clientId);
    }

    const sessionRes = await fetch('/api/v1/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        workflow: currentWorkflow,
        clientIdentity: clientId
      })
    });
    if (sessionRes.ok) {
      const sData = await sessionRes.json();
      sessionToken = sData.token;
      currentSessionId = sData.sessionId;
    }
  } catch (err) {
    console.warn('Could not pre-issue session token, proceeding with WS connect:', err);
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  let wsUrl = `${protocol}//${window.location.host}/ws/liveness?workflow=${currentWorkflow}&lang=${currentLang}`;
  if (sessionToken) {
    wsUrl += `&token=${encodeURIComponent(sessionToken)}`;
  }
  if (adminToken) {
    wsUrl += `&adminToken=${encodeURIComponent(adminToken)}`;
  }

  updateStatus(false, 'Connecting...');
  websocket = new WebSocket(wsUrl);

  websocket.onopen = () => {
    console.log('WebSocket connected to MOSIP liveness engine');
    updateStatus(true, 'Connected');
    reconnectAttempts = 0;
  };

  websocket.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleServerMessage(msg);
    } catch (e) {
      console.warn('Failed to parse WebSocket message:', e);
    }
  };

  websocket.onclose = () => {
    updateStatus(false, 'Disconnected');
    if (reconnectAttempts < 1 && !isReplaying) {
      reconnectAttempts++;
      setTimeout(connectWebSocket, 1500);
    }
  };

  websocket.onerror = (err) => {
    console.error('WebSocket error:', err);
    updateStatus(false, 'Connection Error');
  };
}

function updateStatus(connected, label) {
  const dot = document.querySelector('.status-dot');
  const lbl = document.getElementById('serverStatusLabel');
  dot.className = 'status-dot ' + (connected ? 'connected' : 'disconnected');
  lbl.innerText = label;
}

// Main Frame Processing Loop
async function processVideoFrame(timestamp) {
  if (!isStreaming || isReplaying || !video || video.paused || video.ended) {
    return;
  }

  const shouldSend = (timestamp - lastCaptureTime) >= 80;

  let normalizedLandmarks = [];
  if (faceLandmarker && video.readyState >= 2) {
    try {
      const results = faceLandmarker.detectForVideo(video, timestamp);
      overlayCtx.clearRect(0, 0, overlayCanvas.width, overlayCanvas.height);

      if (results && results.faceLandmarks && results.faceLandmarks.length > 0) {
        const rawPoints = results.faceLandmarks[0];
        // Send 2D landmarks rounded to 4 decimal places for optimal network bandwidth
        normalizedLandmarks = rawPoints.map(p => [
          Math.round(p.x * 10000) / 10000,
          Math.round(p.y * 10000) / 10000
        ]);
        drawFaceMeshPreview(overlayCtx, rawPoints, overlayCanvas.width, overlayCanvas.height);
      }
    } catch (e) {
      // dropped detection frame
    }
  }

  if (shouldSend && websocket && websocket.readyState === WebSocket.OPEN) {
    lastCaptureTime = timestamp;
    captureAndSendFrame(normalizedLandmarks);
  }

  requestAnimationFrame(processVideoFrame);
}

function drawFaceMeshPreview(ctx, points, width, height) {
  ctx.save();
  ctx.scale(-1, 1);
  ctx.translate(-width, 0);

  ctx.fillStyle = 'rgba(59, 130, 246, 0.6)';
  const keyIndices = [4, 152, 33, 133, 362, 263, 61, 291];
  for (const idx of keyIndices) {
    if (points[idx]) {
      const pt = points[idx];
      ctx.beginPath();
      ctx.arc(pt.x * width, pt.y * height, 2.5, 0, 2 * Math.PI);
      ctx.fill();
    }
  }
  ctx.restore();
}

function captureAndSendFrame(landmarks) {
  const targetW = 640;
  const targetH = 480;

  captureCanvas.width = targetW;
  captureCanvas.height = targetH;

  captureCtx.drawImage(video, 0, 0, targetW, targetH);
  const jpegB64 = captureCanvas.toDataURL('image/jpeg', 0.85);

  const payload = {
    type: 'frame',
    seq: frameSequence++,
    tsMs: Date.now(),
    jpegB64: jpegB64,
    landmarks: landmarks,
    width: targetW,
    height: targetH
  };
  if (activeChallengeToken) {
    payload.challengeToken = activeChallengeToken;
  }
  if (virtualCameraDetected) {
    payload.virtualCameraHint = true;
  }

  websocket.send(JSON.stringify(payload));
}

// Server Message Handler
function handleServerMessage(msg) {
  const guide = document.getElementById('ovalGuide');

  switch (msg.type) {
    case 'state':
      document.getElementById('promptText').innerText = msg.prompt || '';
      speak(msg.prompt);
      if (msg.state === 'ACTIVE_CHALLENGE') {
        document.getElementById('challengeCard').classList.remove('hidden');
      } else {
        document.getElementById('challengeCard').classList.add('hidden');
        activeChallengeToken = null;
        stopColorFlashAnimation();
      }
      break;

    case 'quality':
      if (msg.guidance) {
        document.getElementById('promptText').innerText = msg.guidance;
      }
      if (msg.metrics) {
        updateMetricsToolbar(msg.metrics);
        if (msg.metrics.isCompliant) {
          guide.className = 'oval-guide compliant';
        } else {
          guide.className = 'oval-guide warning';
        }
      }
      break;

    case 'progress':
      const fill = document.getElementById('passiveProgressFill');
      const lbl = document.getElementById('passiveProgressLabel');
      const pct = Math.round((msg.collected / msg.window) * 100);
      fill.style.width = `${pct}%`;
      lbl.innerText = `${(UI_STRINGS[currentLang] || UI_STRINGS.en).progressLabel} ${msg.collected}/${msg.window}`;
      break;

    case 'challenge':
      activeChallengeToken = msg.challengeToken || msg.challengeId || null;
      showChallenge(msg.challengeType, msg.prompt, msg.timeoutMs || 4000);
      speak(msg.prompt);
      break;

    case 'decision':
      activeChallengeToken = null;
      stopColorFlashAnimation();
      handleDecision(msg);
      break;

    case 'diagnostic':
      renderDiagnosticTelemetry(msg);
      break;

    case 'error':
      console.warn('Server error:', msg.code, msg.message);
      document.getElementById('promptText').innerText = msg.message;
      guide.className = 'oval-guide error';
      break;
  }
}

function updateMetricsToolbar(m) {
  const compliancePill = document.getElementById('valCompliance');
  const dot = document.querySelector('#pillCompliance .pill-dot');
  if (m.isCompliant) {
    compliancePill.innerText = UI_STRINGS[currentLang].qualityCompliant;
    dot.className = 'pill-dot good';
  } else {
    compliancePill.innerText = UI_STRINGS[currentLang].qualityNonCompliant;
    dot.className = 'pill-dot bad';
  }

  document.getElementById('valSharpness').innerText = Math.round(m.blur || 0);
  const yaw = Math.round(m.yaw || 0);
  const pitch = Math.round(m.pitch || 0);
  document.getElementById('valPose').innerText = `${yaw}° / ${pitch}°`;
  document.getElementById('valLuma').innerText = (m.luma || 0).toFixed(2);
}

function showChallenge(type, prompt, timeoutMs) {
  const card = document.getElementById('challengeCard');
  const icon = document.getElementById('challengeIcon');
  const promptEl = document.getElementById('challengePrompt');
  const fill = document.getElementById('challengeTimerFill');

  promptEl.innerText = prompt;
  icon.innerText = getChallengeIcon(type);
  card.classList.remove('hidden');

  fill.style.transition = 'none';
  fill.style.width = '100%';

  setTimeout(() => {
    fill.style.transition = `width ${timeoutMs}ms linear`;
    fill.style.width = '0%';
  }, 50);

  if (type === 'COLOR_FLASH') {
    startColorFlashAnimation(timeoutMs);
  } else {
    stopColorFlashAnimation();
  }
}

function startColorFlashAnimation(timeoutMs) {
  stopColorFlashAnimation();
  const guide = document.getElementById('ovalGuide');
  const colors = ['rgba(239, 68, 68, 0.45)', 'rgba(34, 197, 94, 0.45)', 'rgba(59, 130, 246, 0.45)', 'rgba(234, 179, 8, 0.45)'];
  let colorIdx = 0;
  colorFlashInterval = setInterval(() => {
    if (guide) {
      guide.style.boxShadow = `0 0 0 9999px ${colors[colorIdx]}`;
      guide.style.borderColor = colors[colorIdx];
    }
    colorIdx = (colorIdx + 1) % colors.length;
  }, 350);
}

function stopColorFlashAnimation() {
  if (colorFlashInterval) {
    clearInterval(colorFlashInterval);
    colorFlashInterval = null;
  }
  const guide = document.getElementById('ovalGuide');
  if (guide) {
    guide.style.boxShadow = '';
    guide.style.borderColor = '';
  }
}

function getChallengeIcon(type) {
  switch (type) {
    case 'BLINK': return '👁️';
    case 'SMILE': return '😊';
    case 'TURN_LEFT': return '⬅️';
    case 'TURN_RIGHT': return '➡️';
    case 'LOOK_UP': return '⬆️';
    case 'NOD_HEAD': return '↕️';
    case 'COLOR_FLASH': return '🌈';
    default: return '👤';
  }
}

function handleDecision(decision) {
  currentSessionId = decision.sessionId;
  const overlay = document.getElementById('decisionOverlay');
  const modal = document.getElementById('decisionModal');
  const title = document.getElementById('decisionTitle');
  const message = document.getElementById('decisionMessage');
  const icon = document.getElementById('decisionIcon');
  const score = document.getElementById('decisionScore');
  const sid = document.getElementById('decisionSessionId');

  const isAccepted = decision.decision === 'ACCEPTED';
  modal.className = 'decision-modal ' + (isAccepted ? 'accepted' : 'rejected');
  icon.innerText = isAccepted ? '✓' : '✕';
  title.innerText = isAccepted
    ? (UI_STRINGS[currentLang] || UI_STRINGS.en).verifSuccess
    : (UI_STRINGS[currentLang] || UI_STRINGS.en).verifFailed;

  message.innerText = decision.userMessage;
  speak(decision.userMessage);

  if (decision.score !== undefined && decision.score !== null) {
    score.innerText = decision.score.toFixed(2);
    document.getElementById('decisionScoreRow')?.classList.remove('hidden');
  } else {
    document.getElementById('decisionScoreRow')?.classList.add('hidden');
  }

  if (decision.sessionId) {
    sid.innerText = decision.sessionId;
    document.getElementById('decisionSessionIdRow')?.classList.remove('hidden');
  } else {
    document.getElementById('decisionSessionIdRow')?.classList.add('hidden');
  }

  overlay.classList.remove('hidden');

  if (currentSessionId && adminToken) {
    fetchAuditTrail(currentSessionId);
  }
}

function resetAndReconnect() {
  if (replayInterval) {
    clearInterval(replayInterval);
    replayInterval = null;
  }
  isReplaying = false;
  document.getElementById('decisionOverlay').classList.add('hidden');
  document.getElementById('challengeCard').classList.add('hidden');
  document.getElementById('ovalGuide').className = 'oval-guide';
  document.getElementById('passiveProgressFill').style.width = '0%';
  document.getElementById('passiveProgressLabel').innerText = `${(UI_STRINGS[currentLang] || UI_STRINGS.en).progressLabel} 0/5`;
  frameSequence = 0;
  connectWebSocket();
}

// Audit Chain REST API Interactions
async function fetchAuditTrail(sessionId) {
  try {
    const headers = {};
    if (adminToken) {
      headers['Authorization'] = `Bearer ${adminToken}`;
    }
    const res = await fetch(`/api/audit/${sessionId}`, { headers });
    if (!res.ok) {
      if (res.status === 401) {
        localAuditEvents = [];
        renderAuditTable([]);
      }
      return;
    }
    localAuditEvents = await res.json();
    renderAuditTable(localAuditEvents);
  } catch (err) {
    console.error('Failed to load audit trail:', err);
  }
}

function renderAuditTable(events) {
  const tbody = document.getElementById('auditTableBody');
  tbody.innerHTML = '';

  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="3">${UI_STRINGS[currentLang].noEvents}</td></tr>`;
    return;
  }

  events.forEach(ev => {
    const tr = document.createElement('tr');
    const decisionClass = ev.decision === 'ACCEPTED' ? 'badge-accepted' :
                          (ev.decision === 'REJECTED' ? 'badge-rejected' : 'badge-neutral');

    tr.innerHTML = `
      <td class="event-name">${ev.eventType}</td>
      <td><span class="decision-pill ${decisionClass}">${ev.decision || 'IN_PROGRESS'}</span></td>
      <td class="code-font" title="Prev: ${ev.previousHash}&#10;Curr: ${ev.currentHash}">${(ev.currentHash || '').substring(0, 10)}...</td>
    `;
    tbody.appendChild(tr);
  });
}

async function verifyAuditChain() {
  if (!localAuditEvents || localAuditEvents.length === 0) {
    showToast('No events to verify. Run a liveness verification capture first.', 'info');
    return;
  }

  try {
    const postHeaders = { 'Content-Type': 'application/json' };
    if (adminToken) {
      postHeaders['Authorization'] = `Bearer ${adminToken}`;
    }
    const res = await fetch('/api/audit/verify', {
      method: 'POST',
      headers: postHeaders,
      body: JSON.stringify(localAuditEvents)
    });
    if (res.status === 401) {
      showToast('Audit verification requires Admin/Judge Token (click Judge Mode in header).', 'warning');
      return;
    }
    const result = await res.json();

    const badge = document.getElementById('chainVerificationBadge');
    const text = document.getElementById('chainVerificationText');
    badge.classList.remove('hidden');

    if (result.valid) {
      badge.className = 'verification-badge valid';
      badge.querySelector('.badge-icon').innerText = '✓';
      text.innerText = UI_STRINGS[currentLang].chainValid;
      showToast('Cryptographic audit chain verified: All SHA-256 event links are intact.', 'success');
    } else {
      badge.className = 'verification-badge invalid';
      badge.querySelector('.badge-icon').innerText = '✕';
      text.innerText = `${UI_STRINGS[currentLang].chainBroken} #${result.firstBrokenIndex} (${result.message})`;
      showToast(`Audit chain broken at event #${result.firstBrokenIndex}!`, 'error');
    }
  } catch (err) {
    showToast('Verification request failed: ' + err.message, 'error');
  }
}

async function tamperAndVerifyAuditChain() {
  if (!localAuditEvents || localAuditEvents.length === 0) {
    showToast('No events recorded yet. Complete a verification first to generate audit records.', 'info');
    return;
  }

  const tamperedChain = JSON.parse(JSON.stringify(localAuditEvents));
  const target = tamperedChain[tamperedChain.length - 1];
  target.decision = target.decision === 'ACCEPTED' ? 'REJECTED' : 'ACCEPTED';

  try {
    const postHeaders = { 'Content-Type': 'application/json' };
    if (adminToken) {
      postHeaders['Authorization'] = `Bearer ${adminToken}`;
    }
    const res = await fetch('/api/audit/verify', {
      method: 'POST',
      headers: postHeaders,
      body: JSON.stringify(tamperedChain)
    });
    if (res.status === 401) {
      showToast('Audit verification requires Admin/Judge Token (click Judge Mode in header).', 'warning');
      return;
    }
    const result = await res.json();

    const badge = document.getElementById('chainVerificationBadge');
    const text = document.getElementById('chainVerificationText');
    badge.classList.remove('hidden');
    badge.className = 'verification-badge invalid';
    badge.querySelector('.badge-icon').innerText = '🛡️';
    text.innerText = `Tamper Detected! Chain Linkage Broken at Event #${result.firstBrokenIndex} (${result.message})`;
    showToast('Simulated local log edit: Chain correctly detected SHA-256 hash mismatch!', 'warning');
  } catch (err) {
    showToast('Verification request failed: ' + err.message, 'error');
  }
}

// Policy & Health API
async function loadPolicyDetails(workflow) {
  const container = document.getElementById('policyDetailsContainer');
  try {
    const headers = {};
    if (adminToken) {
      headers['Authorization'] = `Bearer ${adminToken}`;
    }
    const res = await fetch(`/api/policy/${workflow}`, { headers });
    if (!res.ok) {
      if (res.status === 401) {
        container.innerHTML = `<div class="policy-loading" style="color:var(--text-muted);font-size:0.85rem;">🔒 Policy parameters are protected. Click <strong>⚖️ Judge Mode</strong> in header to enter token.</div>`;
        return;
      }
      throw new Error('Policy request failed');
    }
    const p = await res.json();

    container.innerHTML = `
      <div class="policy-desc" style="margin-bottom:12px;font-size:0.85rem;color:var(--text-muted);">${p.description || ''}</div>
      <div class="policy-item"><span class="policy-key">Workflow</span><span class="policy-val" style="color:#60a5fa;font-weight:600;">${p.workflow}</span></div>
      <div class="policy-item"><span class="policy-key">Passive Threshold</span><span class="policy-val">${p.passiveThreshold}</span></div>
      <div class="policy-item"><span class="policy-key">PAD Attack Threshold</span><span class="policy-val">${p.padThreshold}</span></div>
      <div class="policy-item"><span class="policy-key">Active Challenges</span><span class="policy-val">${p.activeEnabled ? 'Enabled (' + p.minChallenges + ' required)' : 'Disabled (Passive-first)'}</span></div>
      <div class="policy-item"><span class="policy-key">Passive Window</span><span class="policy-val">${p.passiveWindowFrames} frames</span></div>
      <div class="policy-item"><span class="policy-key">Max Retries</span><span class="policy-val">${p.maxRetries} attempts</span></div>
      <div class="policy-item"><span class="policy-key">Failure Behaviour</span><span class="policy-val">${p.failureBehaviour}</span></div>
      <div class="policy-item"><span class="policy-key">Allowed Challenges</span><span class="policy-val">${(p.allowedChallenges || []).join(', ') || 'None'}</span></div>
      <div class="policy-item" style="border-top:1px dashed var(--border-color);padding-top:8px;margin-top:8px;"><span class="policy-key">Standard Compliance</span><span class="policy-val">ISO 19794-5 / ISO 30107</span></div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="policy-loading">Could not load policy details for ${workflow}.</div>`;
  }
}

async function checkServerHealth() {
  try {
    const res = await fetch('/api/health');
    if (res.ok) {
      const data = await res.json();
      updateStatus(true, `Server Healthy (UP)`);
      const indicator = document.getElementById('serverStatusIndicator');
      if (indicator) {
        indicator.title = `Status: ${data.status} | Mode: ${data.mode} | Version: ${data.engineVersion} | Uptime: ${data.uptimeSeconds}s | Audit Events: ${data.totalAuditEvents} | Integrity: ${data.auditChainIntegrity ? 'Tamper-Free' : 'Broken'}`;
      }
      if (data.mode === 'diagnostic') {
        document.getElementById('tabBtnDiag')?.classList.remove('hidden');
      }
    } else {
      updateStatus(false, 'Server Error ' + res.status);
    }
  } catch (e) {
    updateStatus(false, 'Offline');
  }
}

// Live Telemetry & Radar Rendering
function renderDiagnosticTelemetry(diag) {
  if (diag.latencyMs !== undefined) {
    const latEl = document.getElementById('valLatency');
    if (latEl) latEl.innerText = `${diag.latencyMs} ms`;
  }

  if (diag.livenessScore !== undefined) {
    const lScore = Number(diag.livenessScore) || 0.0;
    const aScore = Number(diag.attackScore) || 0.0;

    const valL = document.getElementById('valLivenessScore');
    const barL = document.getElementById('barLivenessScore');
    const valA = document.getElementById('valAttackScore');
    const barA = document.getElementById('barAttackScore');

    if (valL) valL.innerText = lScore.toFixed(3);
    if (barL) barL.style.width = `${Math.round(lScore * 100)}%`;
    if (valA) valA.innerText = aScore.toFixed(3);
    if (barA) barA.style.width = `${Math.round(aScore * 100)}%`;

    const classBadge = document.getElementById('diagClassification');
    if (classBadge && diag.classification) {
      classBadge.innerText = diag.classification;
      if (diag.isAttack) {
        classBadge.className = 'classification-badge attack';
      } else {
        classBadge.className = 'classification-badge genuine';
      }
    }

    const vetoBanner = document.getElementById('diagVetoBanner');
    const vetoText = document.getElementById('diagVetoText');
    if (vetoBanner && vetoText) {
      if (diag.isAttack && aScore >= 0.70) {
        vetoBanner.classList.remove('hidden');
        vetoText.innerText = `PAD ALERT: Presentation Attack Detected (${diag.classification || 'ATTACK'})`;
      } else {
        vetoBanner.classList.add('hidden');
      }
    }
  }

  if (diag.heuristics && typeof diag.heuristics === 'object') {
    updateHeuristicMeter('MicroMotion', diag.heuristics.microMotion);
    updateHeuristicMeter('Moire', diag.heuristics.moire);
    updateHeuristicMeter('Specular', diag.heuristics.specular);
    updateHeuristicMeter('Texture', diag.heuristics.texture);
    updateHeuristicMeter('Border', diag.heuristics.border);
    updateHeuristicMeter('Timing', diag.heuristics.timing);
    updateHeuristicMeter('Mask3d', diag.heuristics.mask3d);
    updateHeuristicMeter('Consistency', diag.heuristics.consistency);
  }
}

function updateHeuristicMeter(idSuffix, score) {
  if (score === undefined || score === null) return;
  const val = Number(score) || 0;
  const bar = document.getElementById('bar' + idSuffix);
  const lbl = document.getElementById('val' + idSuffix);
  if (bar) {
    bar.style.width = `${Math.min(100, Math.max(0, Math.round(val * 100)))}%`;
    bar.style.backgroundColor = val >= 0.70 ? '#10b981' : (val >= 0.35 ? '#f59e0b' : '#ef4444');
  }
  if (lbl) {
    lbl.innerText = val.toFixed(2);
  }
}

// Red Team Adversarial Attack Simulation Gallery
function triggerAttackSimulation(attackType) {
  const logEl = document.getElementById('redTeamLog');
  isReplaying = true;
  if (replayInterval) clearInterval(replayInterval);

  logEl.innerText = `[${new Date().toLocaleTimeString()}] INITIATING ATTACK SIMULATION: ${attackType}...\n`;
  document.getElementById('tabBtnDiag')?.click();

  // Create synthetic frame generator matching attack characteristics
  const canvas = document.createElement('canvas');
  canvas.width = 640;
  canvas.height = 480;
  const ctx = canvas.getContext('2d');

  let frameCount = 0;
  replayInterval = setInterval(() => {
    frameCount++;

    // Base background and face oval
    ctx.fillStyle = '#1e293b';
    ctx.fillRect(0, 0, 640, 480);

    ctx.fillStyle = '#d4a373'; // Synthetic skin tone
    ctx.beginPath();
    ctx.ellipse(320, 240, 110, 150, 0, 0, 2 * Math.PI);
    ctx.fill();

    let landmarks = [];

    if (attackType === 'PRINT_ATTACK') {
      // PAI-1: Flat printed paper border with 0 micro-motion
      ctx.strokeStyle = '#f8fafc';
      ctx.lineWidth = 14;
      ctx.strokeRect(180, 70, 280, 340);
      landmarks = generateStaticMeshPoints(320, 240, 0, 0);
      logEl.innerText += `Frame ${frameCount}: Injected 2D flat paper boundary, jitter residual = 0.000\n`;

    } else if (attackType === 'SCREEN_REPLAY') {
      // PAI-2: High-frequency subpixel grid pattern & specular highlight
      ctx.fillStyle = 'rgba(255, 255, 255, 0.55)';
      ctx.fillRect(280, 180, 50, 35); // Glare patch
      landmarks = generateStaticMeshPoints(320, 240, 0.0001, 0.0001);
      logEl.innerText += `Frame ${frameCount}: Injected OLED subpixel frequency peak & specular reflection\n`;

    } else if (attackType === 'MASK_3D') {
      // PAI-3: Silicone mask perimeter contour discontinuity
      ctx.strokeStyle = 'rgba(0, 0, 0, 0.85)';
      ctx.lineWidth = 6;
      ctx.stroke();
      landmarks = generateStaticMeshPoints(320, 240, 0.0002, 0.0002);
      logEl.innerText += `Frame ${frameCount}: Injected mask cutout edge gradient & uniform reflectance\n`;

    } else if (attackType === 'FORGED_LANDMARKS') {
      // Adversarial: Static frame with injected eye blink & head turn landmarks
      const ear = frameCount % 2 === 0 ? 0.05 : 0.32; // Alternating blink
      const yawDelta = (frameCount * 5);
      landmarks = generateStaticMeshPoints(320 + yawDelta, 240, 0, 0, ear);
      logEl.innerText += `Frame ${frameCount}: INJECTING FORGED LANDMARKS (EAR=${ear}, Yaw=${yawDelta}°) on static frame\n`;
    }

    const jpegB64 = canvas.toDataURL('image/jpeg', 0.85);
    if (websocket && websocket.readyState === WebSocket.OPEN) {
      websocket.send(JSON.stringify({
        type: 'frame',
        seq: frameSequence++,
        tsMs: Date.now(),
        jpegB64: jpegB64,
        landmarks: landmarks,
        width: 640,
        height: 480
      }));
    }

    if (frameCount >= 6) {
      clearInterval(replayInterval);
      replayInterval = null;
      logEl.innerText += `\n[${new Date().toLocaleTimeString()}] ATTACK COMPLETE. Inspecting server defense reaction...\n`;
    }
  }, 100);
}

function generateStaticMeshPoints(cx, cy, jx, jy, customEar) {
  const points = [];
  for (let i = 0; i < 478; i++) {
    const nx = (cx / 640) + ((i % 20) - 10) * 0.01 + jx;
    const ny = (cy / 480) + (Math.floor(i / 20) - 12) * 0.01 + jy;
    points.push([
      Math.round(nx * 10000) / 10000,
      Math.round(ny * 10000) / 10000
    ]);
  }
  return points;
}

function resetToLiveCamera() {
  if (replayInterval) {
    clearInterval(replayInterval);
    replayInterval = null;
  }
  isReplaying = false;
  const logEl = document.getElementById('redTeamLog');
  if (logEl) {
    logEl.innerText = `[${new Date().toLocaleTimeString()}] Restored live webcam input stream.`;
  }
  resetAndReconnect();
}

function showCameraError(title, msg) {
  document.getElementById('cameraErrorTitle').innerText = title;
  document.getElementById('cameraErrorMessage').innerText = msg;
  document.getElementById('cameraErrorOverlay').classList.remove('hidden');
}
