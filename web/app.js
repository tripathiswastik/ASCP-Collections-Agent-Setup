/**
 * Autonomous ASCP Collections Diagnostic Agent - Frontend Application
 * Real-time state synchronizer, interactive SVG lock tree visualizer,
 * Drain log parser studio, live log streaming terminal,
 * and LangGraph Human-in-the-Loop governance gate controller.
 */

document.addEventListener('DOMContentLoaded', () => {
  // API Security Configuration
  // Operator token is kept per session; strictly requires operator input or sessionStorage.
  let API_TOKEN = sessionStorage.getItem('ascpToken') || '';

  const tokenStatusPill = document.getElementById('tokenStatusPill');
  const tokenBadgeLabel = document.getElementById('tokenBadgeLabel');
  const tokenModal = document.getElementById('tokenModal');
  const tokenInput = document.getElementById('tokenInput');
  const btnCloseTokenModal = document.getElementById('btnCloseTokenModal');
  const btnCancelTokenModal = document.getElementById('btnCancelTokenModal');
  const btnSaveTokenModal = document.getElementById('btnSaveTokenModal');

  function updateTokenBadge(label, isUnauthorized = false) {
    if (tokenBadgeLabel) tokenBadgeLabel.textContent = label;
    if (tokenStatusPill) {
      if (isUnauthorized) {
        tokenStatusPill.classList.add('unauthorized');
      } else {
        tokenStatusPill.classList.remove('unauthorized');
      }
    }
  }

  // Initialize initial token badge state
  if (!API_TOKEN) {
    updateTokenBadge('Token: Not Set', true);
  } else {
    updateTokenBadge('Token: Active', false);
  }

  function openTokenModal(isPromptForAuth = false) {
    if (!tokenModal) return;
    if (tokenInput) {
      tokenInput.value = API_TOKEN;
      tokenInput.placeholder = isPromptForAuth ? 'Authentication required. Enter operator token' : 'Enter assigned operator token';
    }
    tokenModal.classList.remove('hidden');
    if (tokenInput) tokenInput.focus();
  }

  function closeTokenModal() {
    if (tokenModal) tokenModal.classList.add('hidden');
  }

  if (tokenStatusPill) {
    tokenStatusPill.addEventListener('click', () => openTokenModal(false));
  }
  if (btnCloseTokenModal) {
    btnCloseTokenModal.addEventListener('click', closeTokenModal);
  }
  if (btnCancelTokenModal) {
    btnCancelTokenModal.addEventListener('click', closeTokenModal);
  }
  if (btnSaveTokenModal) {
    btnSaveTokenModal.addEventListener('click', () => {
      const val = tokenInput ? tokenInput.value.trim() : '';
      if (val) {
        API_TOKEN = val;
        sessionStorage.setItem('ascpToken', API_TOKEN);
        updateTokenBadge('Token: Active', false);
        addConsoleLog('SECURITY', 'Operator authentication token updated and applied.');
      } else {
        API_TOKEN = '';
        sessionStorage.removeItem('ascpToken');
        updateTokenBadge('Token: Not Set', true);
        addConsoleLog('SECURITY', 'Operator authentication token cleared.');
      }
      closeTokenModal();
      refreshTelemetry();
    });
  }

  const apiFetch = async (url, options = {}) => {
    const headers = options.headers ? { ...options.headers } : {};
    if (API_TOKEN) {
      headers['X-API-Token'] = API_TOKEN;
      headers['Authorization'] = `Bearer ${API_TOKEN}`;
    }
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      updateTokenBadge('Token: Invalid (401)', true);
      openTokenModal(true);
    }
    return res;
  };

  // Core Navigation & Selectors
  const scenarioSelector = document.getElementById('scenarioSelector');
  const scenarioPresets = document.getElementById('scenarioPresets');
  const stStatusPill = document.getElementById('stStatusPill');
  const stStatusText = document.getElementById('stStatusText');
  const topologyText = document.getElementById('topologyText');

  // ETL Pipeline Cards
  const stageCardStage1 = document.getElementById('stageCardStage1');
  const stage1Count = document.getElementById('stage1Count');
  const stage1Foot = document.getElementById('stage1Foot');
  const stageCardStage2 = document.getElementById('stageCardStage2');
  const stage2Count = document.getElementById('stage2Count');
  const stage2Foot = document.getElementById('stage2Foot');

  // Agent Console & Action Buttons
  const agentConsoleBody = document.getElementById('agentConsoleBody');
  const btnRunDiagnosis = document.getElementById('btnRunDiagnosis');
  const btnDrainParseOnly = document.getElementById('btnDrainParseOnly');
  const btnClearConsole = document.getElementById('btnClearConsole');
  const btnStreamLogs = document.getElementById('btnStreamLogs');
  const streamLogsText = document.getElementById('streamLogsText');

  // Lock Introspection & Visualizer Controls
  const btnViewSvgTree = document.getElementById('btnViewSvgTree');
  const btnViewCardList = document.getElementById('btnViewCardList');
  const lockSvgContainer = document.getElementById('lockSvgContainer');
  const lockTreeSvg = document.getElementById('lockTreeSvg');
  const lockTreeContainer = document.getElementById('lockTreeContainer');

  // Node Inspector Drawer
  const nodeInspectorDrawer = document.getElementById('nodeInspectorDrawer');
  const btnCloseInspector = document.getElementById('btnCloseInspector');
  const inspectorTitle = document.getElementById('inspectorTitle');
  const inspectorBody = document.getElementById('inspectorBody');
  const inspectorDot = document.getElementById('inspectorDot');

  // Drain Studio
  const drainResultsContainer = document.getElementById('drainResultsContainer');
  const drainStreamStats = document.getElementById('drainStreamStats');

  // ServiceNow Ticket Viewer
  const ticketNumber = document.getElementById('ticketNumber');
  const ticketShortDesc = document.getElementById('ticketShortDesc');
  const ticketBody = document.getElementById('ticketBody');
  const ticketJsonPreview = document.getElementById('ticketJsonPreview');
  const btnCopyJson = document.getElementById('btnCopyJson');

  // HITL Governance Gate Modal
  const hitlModal = document.getElementById('hitlModal');
  const btnCloseModal = document.getElementById('btnCloseModal');
  const btnApproveAction = document.getElementById('btnApproveAction');
  const btnRejectAction = document.getElementById('btnRejectAction');
  const modalApprovalId = document.getElementById('modalApprovalId');
  const modalExpiresAt = document.getElementById('modalExpiresAt');
  const modalActionName = document.getElementById('modalActionName');
  const modalRiskTier = document.getElementById('modalRiskTier');
  const modalTargetObject = document.getElementById('modalTargetObject');
  const modalSessionInfo = document.getElementById('modalSessionInfo');
  const modalSqlPreview = document.getElementById('modalSqlPreview');
  const modalReasoningTrace = document.getElementById('modalReasoningTrace');

  // LangGraph Pipeline Nodes
  const nodeIngestion = document.getElementById('nodeIngestion');
  const nodeClassification = document.getElementById('nodeClassification');
  const nodeLock = document.getElementById('nodeLock');
  const nodeRca = document.getElementById('nodeRca');
  const nodeHitl = document.getElementById('nodeHitl');
  const nodeServiceNow = document.getElementById('nodeServiceNow');

  // Guardrail Meters
  const confidenceMeter = document.getElementById('confidenceMeter');
  const stepMeter = document.getElementById('stepMeter');
  const tokenMeter = document.getElementById('tokenMeter');

  let currentSuperStep = 1;
  let currentTokenSpend = 0.0018;
  let activeTelemetry = [];
  let isStreaming = false;
  let streamTimer = null;
  let activeSessionId = null;
  let activePendingApproval = null;

  // Initialize Dashboard
  init();

  async function init() {
    setupEventListeners();
    try {
      await loadScenarios();
      await refreshTelemetry();
      await loadLockTree();
      await runDrainParsing();
    } catch (err) {
      console.error('Initialization error:', err);
    }
  }

  function setupEventListeners() {
    // Dropdown Scenario Change
    scenarioSelector.addEventListener('change', async (e) => {
      await switchScenario(e.target.value);
    });

    // Preset Scenario Quick Chips
    if (scenarioPresets) {
      scenarioPresets.addEventListener('click', async (e) => {
        const btn = e.target.closest('.preset-chip');
        if (!btn) return;
        const scenKey = btn.getAttribute('data-scenario');
        if (scenKey) {
          await switchScenario(scenKey);
        }
      });
    }

    // View Toggle: SVG Visual Tree vs Card List
    btnViewSvgTree.addEventListener('click', () => {
      btnViewSvgTree.classList.add('active');
      btnViewCardList.classList.remove('active');
      lockSvgContainer.classList.remove('hidden');
      lockTreeContainer.classList.add('hidden');
    });

    btnViewCardList.addEventListener('click', () => {
      btnViewCardList.classList.add('active');
      btnViewSvgTree.classList.remove('active');
      lockTreeContainer.classList.remove('hidden');
      lockSvgContainer.classList.add('hidden');
    });

    // Inspector Close Button
    if (btnCloseInspector) {
      btnCloseInspector.addEventListener('click', () => {
        nodeInspectorDrawer.classList.add('hidden');
      });
    }

    // Agent Action Buttons
    btnRunDiagnosis.addEventListener('click', () => {
      runAutonomousAgent();
    });

    btnDrainParseOnly.addEventListener('click', () => {
      runDrainParsing();
    });

    // Live Streaming Log Terminal
    if (btnStreamLogs) {
      btnStreamLogs.addEventListener('click', () => {
        toggleLiveLogStreaming();
      });
    }

    btnClearConsole.addEventListener('click', () => {
      agentConsoleBody.innerHTML = '';
      addConsoleLog('SYSTEM', 'Console trace cleared.');
    });

    // HITL Modal Actions
    btnCloseModal.addEventListener('click', () => {
      hitlModal.classList.add('hidden');
    });

    btnApproveAction.addEventListener('click', async () => {
      hitlModal.classList.add('hidden');
      addConsoleLog('HUMAN_OPERATOR', 'Signed off on remediation execution. Resuming LangGraph state machine...');
      await resumeAgentExecution(true);
    });

    btnRejectAction.addEventListener('click', async () => {
      hitlModal.classList.add('hidden');
      addConsoleLog('HUMAN_OPERATOR', 'Remediation rejected by DBA. Aborting graph execution.');
      await resumeAgentExecution(false);
    });

    btnCopyJson.addEventListener('click', () => {
      navigator.clipboard.writeText(ticketJsonPreview.textContent).then(() => {
        btnCopyJson.textContent = 'Copied!';
        setTimeout(() => { btnCopyJson.textContent = 'Copy JSON'; }, 2000);
      });
    });
  }

  async function switchScenario(scenKey) {
    if (isStreaming) {
      stopLiveLogStreaming();
    }

    addConsoleLog('CONTROL PLANE', `Switching to scenario preset: ${scenKey}`);
    
    // Update select dropdown
    scenarioSelector.value = scenKey;

    // Update active preset button highlight
    if (scenarioPresets) {
      scenarioPresets.querySelectorAll('.preset-chip').forEach(chip => {
        if (chip.getAttribute('data-scenario') === scenKey) {
          chip.classList.add('active');
        } else {
          chip.classList.remove('active');
        }
      });
    }

    await apiFetch('/api/scenario/load', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: scenKey })
    });

    currentSuperStep = 1;
    currentTokenSpend = 0.0018;
    updateMeters();

    // Close inspector drawer on scenario change
    if (nodeInspectorDrawer) {
      nodeInspectorDrawer.classList.add('hidden');
    }

    await refreshTelemetry();
    await loadLockTree();
    await runDrainParsing();
  }

  async function loadScenarios() {
    try {
      const res = await apiFetch('/api/scenarios');
      if (!res.ok) {
        console.error('Failed to load scenarios: HTTP', res.status);
        return;
      }
      const data = await res.json();
      if (!data || !Array.isArray(data.scenarios)) return;
      scenarioSelector.innerHTML = '';
      data.scenarios.forEach(sc => {
        const opt = document.createElement('option');
        opt.value = sc.key;
        opt.textContent = sc.name;
        scenarioSelector.appendChild(opt);
      });
    } catch (e) {
      console.error('Failed to load scenarios', e);
    }
  }

  async function refreshTelemetry() {
    try {
      const res = await apiFetch('/api/status');
      if (!res.ok) {
        console.error('Failed to refresh status: HTTP', res.status);
        return;
      }
      const data = await res.json();
      if (!data || !data.registry) return;

      const reg = data.registry;
      stStatusText.textContent = `${reg.st_status_name} (${reg.st_status})`;
      
      const dot = stStatusPill.querySelector('.pulse-dot');
      if (reg.st_status === -1) {
        dot.className = 'pulse-dot stalled';
      } else if (reg.st_status === 0) {
        dot.className = 'pulse-dot green';
      } else {
        dot.className = 'pulse-dot stalled';
      }

      if (data.stages && data.stages.length >= 2) {
        const s1 = data.stages[0];
        const s2 = data.stages[1];
        if (stage1Count) stage1Count.textContent = s1.processed_count.toLocaleString();
        if (stage2Count) stage2Count.textContent = s2.processed_count.toLocaleString();

        if (stageCardStage1 && stage1Foot) {
          if (s1.status === 'FAILED') {
            stageCardStage1.classList.add('active-blocked');
            stage1Foot.className = 'stage-status-foot error';
            stage1Foot.textContent = 'STALLED (Snapshot Old / Extraction)';
          } else {
            stageCardStage1.classList.remove('active-blocked');
            stage1Foot.className = 'stage-status-foot success';
            stage1Foot.textContent = 'Extraction Complete';
          }
        }

        if (stageCardStage2 && stage2Foot) {
          if (s2.status === 'STALLED') {
            stageCardStage2.classList.add('active-blocked');
            stage2Foot.className = 'stage-status-foot error';
            stage2Foot.textContent = 'STALLED (Blockage Detected)';
          } else if (s2.status === 'PENDING') {
            stageCardStage2.classList.remove('active-blocked');
            stage2Foot.className = 'stage-status-foot pending';
            stage2Foot.textContent = 'Pending Stage 1';
          } else {
            stageCardStage2.classList.remove('active-blocked');
            stage2Foot.className = 'stage-status-foot success';
            stage2Foot.textContent = 'ODS Loaded';
          }
        }
      }
    } catch (e) {
      console.error('Failed to refresh status', e);
    }
  }

  async function loadLockTree() {
    try {
      const res = await apiFetch('/api/locks');
      if (!res.ok) {
        console.error('Failed to load locks: HTTP', res.status);
        return;
      }
      const data = await res.json();
      activeTelemetry = data.telemetry || [];
      const root = data.root_blocker;

      // 1. Render Interactive SVG Graph
      renderSvgLockTree(activeTelemetry, root);

      // 2. Render Card List View (Tabular)
      renderCardListLocks(activeTelemetry);
    } catch (e) {
      console.error('Failed to load locks', e);
    }
  }

  function renderSvgLockTree(telemetry, root) {
    if (!lockTreeSvg) return;

    if (!telemetry || telemetry.length === 0) {
      // Zero Lock Contention State
      lockTreeSvg.innerHTML = `
        <defs>
          <radialGradient id="greenGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#10b981" stop-opacity="0.25"/>
            <stop offset="100%" stop-color="#10b981" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <circle cx="340" cy="115" r="75" fill="url(#greenGlow)"/>
        <g transform="translate(316, 68)" stroke="#10b981" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </g>
        <text x="340" y="145" text-anchor="middle" fill="#6ee7b7" font-family="'Outfit', sans-serif" font-size="16" font-weight="700">
          Zero Active Lock Contention
        </text>
        <text x="340" y="170" text-anchor="middle" fill="#9ca3af" font-family="'Inter', sans-serif" font-size="12">
          All MSC_ST_* staging tables and snapshot logs report unconstrained parallel concurrency
        </text>
      `;
      return;
    }

    const rootItem = root || telemetry.find(t => t.lock_depth === 1 && !t.blocking_session) || telemetry[0];
    const blockedWorkers = telemetry.filter(t => t !== rootItem && (t.lock_depth > 1 || t.blocking_session));

    let svgHtml = `
      <defs>
        <linearGradient id="rootBgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#ef4444" stop-opacity="0.2"/>
          <stop offset="100%" stop-color="#1f131d" stop-opacity="0.95"/>
        </linearGradient>
        <linearGradient id="workerBgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#f59e0b" stop-opacity="0.15"/>
          <stop offset="100%" stop-color="#151922" stop-opacity="0.95"/>
        </linearGradient>
        <filter id="nodeGlowRed" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#ef4444" flood-opacity="0.5"/>
        </filter>
        <filter id="nodeGlowAmber" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="0" stdDeviation="4" flood-color="#f59e0b" flood-opacity="0.35"/>
        </filter>
        <marker id="arrowLock" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#ef4444"/>
        </marker>
      </defs>
    `;

    // Connectors from root to workers
    const rootBottomX = 340;
    const rootBottomY = 88;

    const workerCoords = [];
    if (blockedWorkers.length === 1) {
      workerCoords.push({ x: 340, y: 168 });
    } else if (blockedWorkers.length === 2) {
      workerCoords.push({ x: 190, y: 168 });
      workerCoords.push({ x: 490, y: 168 });
    } else {
      const step = 600 / (blockedWorkers.length + 1);
      blockedWorkers.forEach((_, i) => {
        workerCoords.push({ x: 40 + step * (i + 1), y: 168 });
      });
    }

    // Draw bezier connectors
    blockedWorkers.forEach((w, idx) => {
      const coords = workerCoords[idx];
      const targetTopX = coords.x;
      const targetTopY = coords.y;
      const ctrlY1 = rootBottomY + 38;
      const ctrlY2 = targetTopY - 38;
      svgHtml += `
        <path d="M ${rootBottomX} ${rootBottomY} C ${rootBottomX} ${ctrlY1}, ${targetTopX} ${ctrlY2}, ${targetTopX} ${targetTopY}"
              class="svg-lock-connector" marker-end="url(#arrowLock)"/>
      `;
    });

    // Draw Root Blocker Node (Top Center)
    const sid = Number(rootItem.sid);
    svgHtml += `
      <g class="svg-lock-node" data-node-type="root" data-sid="${sid}" transform="translate(195, 16)">
        <rect width="290" height="72" rx="8" fill="url(#rootBgGrad)" stroke="#ef4444" stroke-width="1.8" filter="url(#nodeGlowRed)"/>
        
        <!-- Pulsing alert beacon dot -->
        <circle cx="20" cy="22" r="5" fill="#ef4444">
          <animate attributeName="r" values="4;7;4" dur="1.8s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="1;0.4;1" dur="1.8s" repeatCount="indefinite"/>
        </circle>

        <!-- Node Header & Badges -->
        <text x="34" y="24" fill="#ffffff" font-family="'JetBrains Mono', monospace" font-size="12" font-weight="700">
          ROOT BLOCKER: SID ${sid}
        </text>
        <rect x="180" y="11" width="98" height="18" rx="4" fill="#ef4444" fill-opacity="0.25" stroke="#ef4444" stroke-width="0.8"/>
        <text x="229" y="23" text-anchor="middle" fill="#fca5a5" font-family="'JetBrains Mono', monospace" font-size="9" font-weight="600">
          EXCLUSIVE (X)
        </text>

        <!-- Subtitle Details -->
        <text x="20" y="44" fill="#cbd5e1" font-family="'Inter', sans-serif" font-size="11">
          Target: <tspan fill="#f87171" font-weight="600" font-family="'JetBrains Mono', monospace">${escapeHtml(rootItem.object_name)}</tspan> | User: ${escapeHtml(rootItem.oracle_username)}
        </text>
        <text x="20" y="60" fill="#94a3b8" font-family="'Inter', sans-serif" font-size="10">
          Module: <tspan fill="#e2e8f0">${escapeHtml(rootItem.module || 'SQL*Plus')}</tspan> (${escapeHtml(rootItem.action || 'MANUAL')}) \u2022 Click to Inspect
        </text>
      </g>
    `;

    // Draw Blocked Workers Nodes
    blockedWorkers.forEach((w, idx) => {
      const coords = workerCoords[idx];
      const boxW = 240;
      const boxH = 68;
      const leftX = coords.x - (boxW / 2);
      const topY = coords.y;
      const wSid = Number(w.sid);

      svgHtml += `
        <g class="svg-lock-node" data-node-type="worker" data-sid="${wSid}" transform="translate(${leftX}, ${topY})">
          <rect width="${boxW}" height="${boxH}" rx="8" fill="url(#workerBgGrad)" stroke="#f59e0b" stroke-width="1.4" filter="url(#nodeGlowAmber)"/>
          
          <!-- Mode 0 Waiting Badge -->
          <circle cx="18" cy="20" r="4.5" fill="#f59e0b"/>
          <text x="30" y="23" fill="#ffffff" font-family="'JetBrains Mono', monospace" font-size="11" font-weight="700">
            WORKER: SID ${wSid}
          </text>
          <rect x="${boxW - 82}" y="10" width="72" height="17" rx="3" fill="#f59e0b" fill-opacity="0.2" stroke="#f59e0b" stroke-width="0.7"/>
          <text x="${boxW - 46}" y="22" text-anchor="middle" fill="#fcd34d" font-family="'JetBrains Mono', monospace" font-size="8.5" font-weight="600">
            MODE 0 WAIT
          </text>

          <!-- Worker Details -->
          <text x="18" y="42" fill="#cbd5e1" font-family="'Inter', sans-serif" font-size="10.5">
            Process: <tspan fill="#fde68a" font-family="'JetBrains Mono', monospace">${escapeHtml(w.module)}</tspan>
          </text>
          <text x="18" y="56" fill="#94a3b8" font-family="'Inter', sans-serif" font-size="9.5">
            ${escapeHtml(w.action || 'ODS_LOAD_WORKER')} &bull; Click to Inspect
          </text>
        </g>
      `;
    });

    lockTreeSvg.innerHTML = svgHtml;

    // Attach click handlers to all SVG nodes
    lockTreeSvg.querySelectorAll('.svg-lock-node').forEach(nodeEl => {
      nodeEl.addEventListener('click', (e) => {
        const sid = parseInt(nodeEl.getAttribute('data-sid'), 10);
        const item = telemetry.find(t => t.sid === sid) || telemetry[0];
        openNodeInspector(item);
      });
    });
  }

  function openNodeInspector(item) {
    if (!nodeInspectorDrawer || !item) return;

    const isRoot = item.lock_depth === 1 && !item.blocking_session;
    inspectorTitle.textContent = `SID ${item.sid} (SERIAL# ${item.serial_number}): ${isRoot ? 'Root Blocker' : 'Blocked Worker'}`;
    
    if (inspectorDot) {
      inspectorDot.className = `pulse-dot ${isRoot ? 'stalled' : 'waiting'}`;
    }

    // Simulated Undo Volume Check for V$TRANSACTION
    const usedUrec = item.sid === 999 ? 150000 : (isRoot ? 420 : 0);
    const isHighRisk = usedUrec > 100000;
    const estRollback = (usedUrec * 0.0003).toFixed(1);

    // Build inspector details using safe textContent to prevent XSS
    inspectorBody.textContent = '';

    const addInspectorRow = (label, val, valStyle = '') => {
      const row = document.createElement('div');
      row.className = 'inspector-row';
      const lSpan = document.createElement('span');
      lSpan.className = 'inspector-label';
      lSpan.textContent = label;
      const vSpan = document.createElement('span');
      vSpan.className = 'inspector-val';
      vSpan.textContent = String(val);
      if (valStyle) vSpan.style.cssText = valStyle;
      row.appendChild(lSpan);
      row.appendChild(vSpan);
      inspectorBody.appendChild(row);
    };

    addInspectorRow('Session ID / Serial:', `SID ${item.sid}, SERIAL# ${item.serial_number}`);
    addInspectorRow('Oracle User / OS:', `${item.oracle_username} (${item.os_user_name || 'applmgr'})`);
    addInspectorRow('Target Table:', item.object_name, 'color:#f87171;');
    addInspectorRow('Lock Mode:', `Mode ${item.locked_mode}: ${item.locked_mode_text}`, `color:${isRoot ? '#ef4444' : '#f59e0b'};`);
    addInspectorRow('Client Module:', item.module || 'SQL*Plus');
    addInspectorRow('Active Action:', item.action || 'NONE');

    // Undo Records block
    const undoWrap = document.createElement('div');
    undoWrap.style.marginTop = '0.25rem';
    const undoLbl = document.createElement('span');
    undoLbl.className = 'inspector-label';
    undoLbl.style.display = 'block';
    undoLbl.style.marginBottom = '0.25rem';
    undoLbl.textContent = 'V$TRANSACTION Undo Records (USED_UREC):';
    undoWrap.appendChild(undoLbl);

    const undoBadge = document.createElement('div');
    undoBadge.className = `inspector-undo-badge ${isHighRisk ? 'danger' : ''}`;
    const span1 = document.createElement('span');
    span1.textContent = `${usedUrec.toLocaleString()} Undo Records`;
    const span2 = document.createElement('span');
    span2.textContent = ` • Est Rollback: ${estRollback}s`;
    const span3 = document.createElement('span');
    span3.textContent = ` • ${isHighRisk ? 'HIGH PMON RISK' : 'SAFE FOR TERMINATION'}`;
    undoBadge.appendChild(span1);
    undoBadge.appendChild(span2);
    undoBadge.appendChild(span3);
    undoWrap.appendChild(undoBadge);
    inspectorBody.appendChild(undoWrap);

    // SQL block
    const sqlWrap = document.createElement('div');
    sqlWrap.style.marginTop = '0.25rem';
    const sqlLbl = document.createElement('span');
    sqlLbl.className = 'inspector-label';
    sqlLbl.style.display = 'block';
    sqlLbl.style.marginBottom = '0.25rem';
    sqlLbl.textContent = 'Current Executing SQL (V$SQL):';
    sqlWrap.appendChild(sqlLbl);

    const sqlBox = document.createElement('div');
    sqlBox.className = 'inspector-sql';
    sqlBox.textContent = item.current_sql_text || 'SELECT /* Idle uncommitted transaction */ FROM DUAL';
    sqlWrap.appendChild(sqlBox);
    inspectorBody.appendChild(sqlWrap);

    // Stage Kill Remediation button if root
    if (isRoot) {
      const btnWrap = document.createElement('div');
      btnWrap.style.marginTop = '0.5rem';
      btnWrap.style.display = 'flex';
      btnWrap.style.gap = '0.5rem';

      const btnKill = document.createElement('button');
      btnKill.className = 'btn-xs btn-danger';
      btnKill.id = 'btnDraftKillSession';
      btnKill.style.cssText = 'flex:1; padding:0.4rem; background:rgba(239,68,68,0.2); border:1px solid #ef4444; color:#fca5a5; border-radius:4px; font-weight:600; cursor:pointer;';
      btnKill.textContent = 'Stage Kill Remediation (HITL)';
      btnKill.addEventListener('click', () => {
        openHitlModal({
          action: 'KILL_SESSION',
          risk_tier: 'HIGH',
          target_object: item.object_name,
          target_sid: item.sid,
          target_serial: item.serial_number,
          recommended_sql: `ALTER SYSTEM KILL SESSION '${item.sid},${item.serial_number}' IMMEDIATE;`,
          reasoning: `Manual session ${item.sid} is holding Mode 6 Exclusive lock on ${item.object_name}, blocking parallel MSCPDCW workers.`
        });
      });
      btnWrap.appendChild(btnKill);
      inspectorBody.appendChild(btnWrap);
    }

    nodeInspectorDrawer.classList.remove('hidden');
  }

  function renderCardListLocks(telemetry) {
    if (!lockTreeContainer) return;
    lockTreeContainer.textContent = '';

    if (!telemetry || telemetry.length === 0) {
      const emptyCard = document.createElement('div');
      emptyCard.className = 'lock-node-card';
      const emptyHeader = document.createElement('div');
      emptyHeader.className = 'lock-card-header';
      const b1 = document.createElement('span');
      b1.className = 'session-badge';
      b1.textContent = 'No Active Blockages';
      const b2 = document.createElement('span');
      b2.className = 'mode-badge waiting';
      b2.textContent = 'Zero Lock Contention';
      emptyHeader.appendChild(b1);
      emptyHeader.appendChild(b2);
      emptyCard.appendChild(emptyHeader);

      const p = document.createElement('p');
      p.style.cssText = 'font-size:0.8rem; color:var(--text-muted);';
      p.textContent = 'All MSC_ST_* interface tables and snapshot logs report unconstrained concurrency.';
      emptyCard.appendChild(p);
      lockTreeContainer.appendChild(emptyCard);
      return;
    }

    telemetry.forEach(item => {
      const isRoot = item.lock_depth === 1;
      const card = document.createElement('div');
      card.className = `lock-node-card ${isRoot ? 'root-blocker' : 'blocked-worker'}`;

      const header = document.createElement('div');
      header.className = 'lock-card-header';
      const sBadge = document.createElement('span');
      sBadge.className = 'session-badge';
      sBadge.textContent = `SID ${item.sid} (SERIAL# ${item.serial_number})`;
      const mBadge = document.createElement('span');
      mBadge.className = `mode-badge ${isRoot ? '' : 'waiting'}`;
      mBadge.textContent = `Mode ${item.locked_mode}: ${item.locked_mode_text}`;
      header.appendChild(sBadge);
      header.appendChild(mBadge);
      card.appendChild(header);

      const details = document.createElement('div');
      details.className = 'lock-card-details';

      const createDetailRow = (lbl, val, isCode = false) => {
        const row = document.createElement('div');
        const lSpan = document.createElement('span');
        lSpan.style.color = 'var(--text-dim)';
        lSpan.textContent = lbl + ': ';
        const vEl = document.createElement(isCode ? 'code' : 'strong');
        vEl.textContent = String(val);
        row.appendChild(lSpan);
        row.appendChild(vEl);
        return row;
      };

      details.appendChild(createDetailRow('User', `${item.oracle_username} (${item.os_user_name || 'applmgr'})`));
      details.appendChild(createDetailRow('Object', item.object_name, true));
      details.appendChild(createDetailRow('Module', item.module || 'SQL*Plus'));
      details.appendChild(createDetailRow('Action', item.action || 'NONE'));
      card.appendChild(details);

      const sqlBox = document.createElement('div');
      sqlBox.className = 'lock-sql-box';
      const code = document.createElement('code');
      code.textContent = item.current_sql_text || 'SELECT /* Idle or uncommitted transaction */ FROM DUAL';
      sqlBox.appendChild(code);
      card.appendChild(sqlBox);

      lockTreeContainer.appendChild(card);
    });
  }

  // Live Log Streaming & Real-Time Drain Parsing
  async function toggleLiveLogStreaming() {
    if (isStreaming) {
      stopLiveLogStreaming();
    } else {
      await startLiveLogStreaming();
    }
  }

  async function startLiveLogStreaming() {
    isStreaming = true;
    if (btnStreamLogs) {
      btnStreamLogs.classList.add('streaming');
      streamLogsText.textContent = 'Pause Log Stream';
    }

    // Retrieve active scenario logs
    let logs = [];
    try {
      const scenRes = await apiFetch('/api/status');
      const scenData = await scenRes.json();
      logs = scenData.scenario.logs || [];
    } catch (e) {
      logs = [
        "[12-OCT-2025 04:12:01]: Launching Planning ODS Load Worker 1 (MSCPDCW)",
        "[12-OCT-2025 04:12:05]: Cause: ORA-00054: resource busy and acquire with NOWAIT specified on table MSC_ST_DEMANDS.",
        "[12-OCT-2025 04:12:06]: Action: Contact DBA to verify blocking locks on staging tables.",
        "[12-OCT-2025 04:12:10]: Worker process 31902 terminated with fatal error status."
      ];
    }

    addConsoleLog('STREAM', `--- Initiating Live Log Telemetry Stream (${logs.length} events) ---`);
    if (drainStreamStats) {
      drainStreamStats.textContent = `Streaming Active \u2022 0 / ${logs.length} Lines`;
    }

    let lineIndex = 0;
    const accumulatedLogs = [];

    streamTimer = setInterval(async () => {
      if (lineIndex >= logs.length) {
        stopLiveLogStreaming();
        addConsoleLog('STREAM', '--- End of Real-Time Log Ingestion Stream ---');
        return;
      }

      const line = logs[lineIndex];
      accumulatedLogs.push(line);
      lineIndex++;

      // Append to agent console
      addConsoleLog('LOG_IN', line);

      if (drainStreamStats) {
        drainStreamStats.textContent = `Streaming: ${lineIndex}/${logs.length} Lines`;
      }

      // Increment token spend & step progress
      currentTokenSpend += 0.0003;
      updateMeters();

      // Trigger incremental Drain parse
      try {
        const parseRes = await apiFetch('/api/parse-log', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ log_text: accumulatedLogs.join('\n') })
        });
        const parseData = await parseRes.json();
        renderDrainClusters(parseData.results || []);
      } catch (err) {
        // Fallback gracefully
      }
    }, 400);
  }

  function stopLiveLogStreaming() {
    isStreaming = false;
    if (streamTimer) {
      clearInterval(streamTimer);
      streamTimer = null;
    }
    if (btnStreamLogs) {
      btnStreamLogs.classList.remove('streaming');
      streamLogsText.textContent = 'Stream Logs Live';
    }
    if (drainStreamStats) {
      drainStreamStats.textContent = 'Stream Complete \u2022 Fixed-Depth Tree Ready';
    }
  }

  function renderDrainClusters(results) {
    if (!drainResultsContainer) return;
    drainResultsContainer.textContent = '';

    results.forEach(item => {
      const card = document.createElement('div');
      card.className = 'drain-cluster-card';

      const header = document.createElement('div');
      header.className = 'drain-cluster-header';
      const cSpan = document.createElement('span');
      cSpan.textContent = `Cluster #${item.cluster_id}`;
      const mSpan = document.createElement('span');
      mSpan.textContent = 'Drain Tree Match';
      header.appendChild(cSpan);
      header.appendChild(mSpan);
      card.appendChild(header);

      const template = document.createElement('div');
      template.className = 'drain-template';
      template.textContent = item.template || '';
      card.appendChild(template);

      const paramsGrid = document.createElement('div');
      paramsGrid.className = 'drain-params-grid';
      if (item.parameters) {
        for (const [k, v] of Object.entries(item.parameters)) {
          const badge = document.createElement('span');
          badge.className = 'param-badge';
          const valDisplay = Array.isArray(v) ? v.join(', ') : v;
          badge.textContent = `${k}: ${valDisplay}`;
          paramsGrid.appendChild(badge);
        }
      }
      card.appendChild(paramsGrid);
      drainResultsContainer.appendChild(card);
    });
  }

  async function runDrainParsing() {
    try {
      const res = await apiFetch('/api/parse-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();
      renderDrainClusters(data.results || []);
    } catch (e) {
      console.error('Failed to parse logs', e);
    }
  }

  async function runAutonomousAgent() {
    // 1. Immediately halt live log streaming if running
    if (isStreaming) {
      stopLiveLogStreaming();
    }

    addConsoleLog('AGENT', 'Starting LangGraph 6-Step Autonomous Diagnostic Graph...');
    setActiveNode('nodeIngestion');

    btnRunDiagnosis.disabled = true;
    btnRunDiagnosis.innerHTML = `
      <svg class="spinner" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
        <path d="M12 2a10 10 0 0 1 10 10"></path>
      </svg>
      Analyzing...
    `;

    const selectedScenario = scenarioSelector ? scenarioSelector.value : 'ora_00054_mode6';

    try {
      setActiveNode('nodeClassification');

      const res = await apiFetch('/api/diagnose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'START',
          scenario_key: selectedScenario
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `Server responded with HTTP ${res.status}`);
      }

      activeSessionId = data.session_id;

      // Update confidence meter if available
      if (data.state && data.state.confidence_score) {
        confidenceMeter.textContent = `${data.state.confidence_score.toFixed(1)}%`;
      }

      // Render messages in console
      if (data.state && data.state.messages) {
        data.state.messages.forEach(m => {
          const role = (m.role || 'assistant').toUpperCase();
          const content = m.content || '';
          if (content.includes('[SIMULATED]') || content.toLowerCase().includes('remediation') || content.toLowerCase().includes('extended')) {
            addConsoleLog('REMEDIATION', content);
          } else {
            addConsoleLog(role, content);
          }
        });
      }

      // If HITL interrupt triggered
      if (data.interrupted && data.interrupt_payload) {
        currentSuperStep = 5;
        currentTokenSpend += 0.0022;
        updateMeters();
        activePendingApproval = data.interrupt_payload;
        setActiveNode('nodeHitl');
        openHitlModal(data.interrupt_payload);
      } else {
        // Fully autonomous resolution (e.g. Scenario 8: ORA-01555 low risk auto-remediated)
        setActiveNode('nodeServiceNow');
        currentSuperStep = 10;
        currentTokenSpend += 0.0035;
        updateMeters();

        if (data.remediation_success || (data.state && data.state.is_remediated)) {
          addConsoleLog('REMEDIATION', 'Autonomous remediation completed successfully. ST_STATUS normalized to 0.');
        }

        // Refresh telemetry & lock tree so pipeline reflects normalized status
        await refreshTelemetry();
        await loadLockTree();
      }

      // Update ServiceNow Ticket Card if already created
      if (data.state && data.state.servicenow_incident) {
        renderServiceNowTicket(data.state.servicenow_incident);
      }
    } catch (e) {
      console.error('Agent invocation error', e);
      addConsoleLog('ERROR', e.message);
    } finally {
      btnRunDiagnosis.disabled = false;
      btnRunDiagnosis.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        Run Autonomous Diagnosis
      `;
    }
  }

  async function resumeAgentExecution(approved) {
    setActiveNode('nodeRemediation');
    const payload = activePendingApproval || {};
    const resumePayload = {
      action: 'RESUME',
      session_id: activeSessionId,
      approved: approved,
      approval_id: payload.approval_id,
      target_action: payload.action,
      target_sid: payload.target_sid,
      target_serial: payload.target_serial,
      target_object: payload.target_object,
      dba_user: 'DBA_OPERATOR',
      notes: approved ? 'Approved via Web Dashboard HITL Gate' : 'Rejected by DBA operator'
    };

    try {
      const res = await apiFetch('/api/diagnose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(resumePayload)
      });
      const data = await res.json();

      if (!res.ok) {
        addConsoleLog('ERROR', data.error || 'Remediation request rejected by server');
        return;
      }

      currentSuperStep += 1;
      currentTokenSpend += 0.0008;
      updateMeters();

      if (data.state && data.state.messages) {
        const lastMsg = data.state.messages[data.state.messages.length - 1];
        addConsoleLog('REMEDIATION', lastMsg.content);
      }

      // Refresh pipeline status post-remediation
      await refreshTelemetry();
      await loadLockTree();
    } catch (e) {
      console.error('Resumption error', e);
      addConsoleLog('ERROR', e.message);
    }
  }

  function openHitlModal(payload) {
    activePendingApproval = payload;
    if (modalApprovalId) modalApprovalId.textContent = payload.approval_id || 'appr-pending';
    if (modalExpiresAt) modalExpiresAt.textContent = payload.expires_at_iso || '5m Window';
    modalActionName.textContent = payload.action;
    modalRiskTier.textContent = `${payload.risk_tier} RISK`;
    modalTargetObject.textContent = payload.target_object || 'MSC_ST_DEMANDS';
    modalSessionInfo.textContent = payload.target_sid ? `SID ${payload.target_sid} (SERIAL# ${payload.target_serial})` : 'N/A';
    modalSqlPreview.textContent = payload.recommended_sql;
    modalReasoningTrace.textContent = payload.reasoning;

    hitlModal.classList.remove('hidden');
  }

  function renderServiceNowTicket(incident) {
    ticketNumber.textContent = incident.incident_number || 'INC084192';
    const payload = incident.payload || {};
    ticketShortDesc.textContent = payload.short_description || 'AUTONOMOUS DIAGNOSTIC REPORT';
    ticketBody.textContent = payload.description || '';
    ticketJsonPreview.textContent = JSON.stringify(payload.u_diagnostic_payload || payload, null, 2);
  }

  function setActiveNode(nodeId) {
    [nodeIngestion, nodeClassification, nodeLock, nodeRca, nodeHitl, nodeServiceNow].forEach(el => {
      if (el) el.classList.remove('active');
    });
    const target = document.getElementById(nodeId);
    if (target) target.classList.add('active');
  }

  function updateMeters() {
    stepMeter.textContent = `${currentSuperStep} / 10`;
    tokenMeter.textContent = `$${currentTokenSpend.toFixed(3)} / $5.00 (illustrative)`;
  }

  function addConsoleLog(speaker, text) {
    const item = document.createElement('div');
    item.className = `console-log-item ${(speaker || 'system').toLowerCase()}`;
    const time = new Date().toTimeString().split(' ')[0];

    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.textContent = `[${time}]`;

    const speakerSpan = document.createElement('span');
    speakerSpan.className = 'log-speaker';
    speakerSpan.textContent = `[${speaker}]`;

    const textSpan = document.createElement('span');
    textSpan.textContent = String(text ?? '');

    item.appendChild(timeSpan);
    item.appendChild(document.createTextNode(' '));
    item.appendChild(speakerSpan);
    item.appendChild(document.createTextNode(' '));
    item.appendChild(textSpan);

    agentConsoleBody.appendChild(item);
    agentConsoleBody.scrollTop = agentConsoleBody.scrollHeight;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
});
