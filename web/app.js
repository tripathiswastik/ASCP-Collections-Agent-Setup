/**
 * Autonomous ASCP Collections Diagnostic Agent - Frontend Application
 * Real-time state synchronizer, lock tree renderer, Drain log parser studio,
 * and LangGraph Human-in-the-Loop governance gate controller.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const scenarioSelector = document.getElementById('scenarioSelector');
  const stStatusPill = document.getElementById('stStatusPill');
  const stStatusText = document.getElementById('stStatusText');
  const topologyText = document.getElementById('topologyText');

  const stage1Count = document.getElementById('stage1Count');
  const stage1Foot = document.getElementById('stage1Foot');
  const stage2Count = document.getElementById('stage2Count');
  const stage2Foot = document.getElementById('stage2Foot');
  const stageCardStage2 = document.getElementById('stageCardStage2');

  const agentConsoleBody = document.getElementById('agentConsoleBody');
  const btnRunDiagnosis = document.getElementById('btnRunDiagnosis');
  const btnDrainParseOnly = document.getElementById('btnDrainParseOnly');
  const btnClearConsole = document.getElementById('btnClearConsole');

  const lockTreeContainer = document.getElementById('lockTreeContainer');
  const drainResultsContainer = document.getElementById('drainResultsContainer');

  const ticketNumber = document.getElementById('ticketNumber');
  const ticketShortDesc = document.getElementById('ticketShortDesc');
  const ticketBody = document.getElementById('ticketBody');
  const ticketJsonPreview = document.getElementById('ticketJsonPreview');
  const btnCopyJson = document.getElementById('btnCopyJson');

  const hitlModal = document.getElementById('hitlModal');
  const btnCloseModal = document.getElementById('btnCloseModal');
  const btnApproveAction = document.getElementById('btnApproveAction');
  const btnRejectAction = document.getElementById('btnRejectAction');
  const modalActionName = document.getElementById('modalActionName');
  const modalRiskTier = document.getElementById('modalRiskTier');
  const modalTargetObject = document.getElementById('modalTargetObject');
  const modalSessionInfo = document.getElementById('modalSessionInfo');
  const modalSqlPreview = document.getElementById('modalSqlPreview');
  const modalReasoningTrace = document.getElementById('modalReasoningTrace');

  const nodeIngestion = document.getElementById('nodeIngestion');
  const nodeClassification = document.getElementById('nodeClassification');
  const nodeLock = document.getElementById('nodeLock');
  const nodeRca = document.getElementById('nodeRca');
  const nodeHitl = document.getElementById('nodeHitl');
  const nodeServiceNow = document.getElementById('nodeServiceNow');

  const confidenceMeter = document.getElementById('confidenceMeter');
  const stepMeter = document.getElementById('stepMeter');
  const tokenMeter = document.getElementById('tokenMeter');

  let currentSuperStep = 1;
  let currentTokenSpend = 0.0018;

  // Initialize Dashboard
  init();

  async function init() {
    await loadScenarios();
    await refreshTelemetry();
    await loadLockTree();
    await runDrainParsing();

    setupEventListeners();
  }

  function setupEventListeners() {
    scenarioSelector.addEventListener('change', async (e) => {
      const selectedKey = e.target.value;
      addConsoleLog('CONTROL PLANE', `Switching to scenario: ${selectedKey}`);
      await fetch('/api/scenario/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: selectedKey })
      });
      currentSuperStep = 1;
      currentTokenSpend = 0.0018;
      updateMeters();
      await refreshTelemetry();
      await loadLockTree();
      await runDrainParsing();
    });

    btnRunDiagnosis.addEventListener('click', () => {
      runAutonomousAgent();
    });

    btnDrainParseOnly.addEventListener('click', () => {
      runDrainParsing();
    });

    btnClearConsole.addEventListener('click', () => {
      agentConsoleBody.innerHTML = '';
      addConsoleLog('SYSTEM', 'Console trace cleared.');
    });

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

  async function loadScenarios() {
    try {
      const res = await fetch('/api/scenarios');
      const data = await res.json();
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
      const res = await fetch('/api/status');
      const data = await res.json();

      const reg = data.registry;
      stStatusText.textContent = `${reg.st_status_name} (${reg.st_status})`;
      
      const dot = stStatusPill.querySelector('.pulse-dot');
      if (reg.st_status === -1) {
        dot.className = 'pulse-dot stalled';
        stageCardStage2.classList.add('active-blocked');
        stage2Foot.className = 'stage-status-foot error';
        stage2Foot.textContent = 'STALLED (Blockage Detected)';
      } else if (reg.st_status === 0) {
        dot.className = 'pulse-dot green';
        stageCardStage2.classList.remove('active-blocked');
        stage2Foot.className = 'stage-status-foot success';
        stage2Foot.textContent = 'ODS Loaded';
      }

      if (data.stages && data.stages.length >= 2) {
        stage1Count.textContent = data.stages[0].processed_count.toLocaleString();
        stage2Count.textContent = data.stages[1].processed_count.toLocaleString();
      }
    } catch (e) {
      console.error('Failed to refresh status', e);
    }
  }

  async function loadLockTree() {
    try {
      const res = await fetch('/api/locks');
      const data = await res.json();
      lockTreeContainer.innerHTML = '';

      if (!data.telemetry || data.telemetry.length === 0) {
        lockTreeContainer.innerHTML = `
          <div class="lock-node-card">
            <div class="lock-card-header">
              <span class="session-badge">No Active Blockages</span>
              <span class="mode-badge waiting">Zero Lock Contention</span>
            </div>
            <p style="font-size:0.8rem; color:var(--text-muted);">
              All MSC_ST_* interface tables and snapshot logs report unconstrained concurrency.
            </p>
          </div>
        `;
        return;
      }

      data.telemetry.forEach(item => {
        const isRoot = item.lock_depth === 1;
        const card = document.createElement('div');
        card.className = `lock-node-card ${isRoot ? 'root-blocker' : 'blocked-worker'}`;

        card.innerHTML = `
          <div class="lock-card-header">
            <span class="session-badge">SID ${item.sid} (SERIAL# ${item.serial_number})</span>
            <span class="mode-badge ${isRoot ? '' : 'waiting'}">
              Mode ${item.locked_mode}: ${item.locked_mode_text}
            </span>
          </div>
          <div class="lock-card-details">
            <div><span style="color:var(--text-dim)">User:</span> <strong>${item.oracle_username} (${item.os_user_name})</strong></div>
            <div><span style="color:var(--text-dim)">Object:</span> <code>${item.object_name}</code></div>
            <div><span style="color:var(--text-dim)">Module:</span> <strong>${item.module}</strong></div>
            <div><span style="color:var(--text-dim)">Action:</span> <span>${item.action || 'NONE'}</span></div>
          </div>
          <div class="lock-sql-box">
            <code>${item.current_sql_text || 'SELECT /* Idle or uncommitted transaction */ FROM DUAL'}</code>
          </div>
        `;
        lockTreeContainer.appendChild(card);
      });
    } catch (e) {
      console.error('Failed to load locks', e);
    }
  }

  async function runDrainParsing() {
    try {
      const res = await fetch('/api/parse-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();
      drainResultsContainer.innerHTML = '';

      data.results.forEach(item => {
        const card = document.createElement('div');
        card.className = 'drain-cluster-card';

        let paramsHtml = '';
        if (item.parameters) {
          for (const [k, v] of Object.entries(item.parameters)) {
            const valDisplay = Array.isArray(v) ? v.join(', ') : v;
            paramsHtml += `<span class="param-badge">${k}: ${valDisplay}</span>`;
          }
        }

        card.innerHTML = `
          <div class="drain-cluster-header">
            <span>Cluster #${item.cluster_id}</span>
            <span>Drain Tree Match</span>
          </div>
          <div class="drain-template">${escapeHtml(item.template)}</div>
          <div class="drain-params-grid">${paramsHtml}</div>
        `;
        drainResultsContainer.appendChild(card);
      });
    } catch (e) {
      console.error('Failed to parse logs', e);
    }
  }

  async function runAutonomousAgent() {
    addConsoleLog('AGENT', 'Starting LangGraph 6-Step Autonomous Diagnostic Graph...');
    setActiveNode('nodeIngestion');

    btnRunDiagnosis.disabled = true;
    btnRunDiagnosis.innerHTML = 'Analyzing...';

    try {
      const res = await fetch('/api/diagnose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'START' })
      });
      const data = await res.json();

      currentSuperStep += 3;
      currentTokenSpend += 0.0022;

      // Update confidence meter if available
      if (data.state && data.state.confidence_score) {
        confidenceMeter.textContent = `${data.state.confidence_score.toFixed(1)}%`;
      }
      updateMeters();

      // Render messages in console
      if (data.state && data.state.messages) {
        data.state.messages.forEach(m => {
          addConsoleLog(m.role.toUpperCase(), m.content);
        });
      }

      // If HITL interrupt triggered
      if (data.interrupted && data.interrupt_payload) {
        setActiveNode('nodeHitl');
        openHitlModal(data.interrupt_payload);
      } else {
        setActiveNode('nodeServiceNow');
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
    try {
      const res = await fetch('/api/diagnose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'RESUME', approved: approved })
      });
      const data = await res.json();

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
    tokenMeter.textContent = `$${currentTokenSpend.toFixed(3)} / $5.00`;
  }

  function addConsoleLog(speaker, text) {
    const item = document.createElement('div');
    item.className = `console-log-item ${speaker.toLowerCase()}`;
    const time = new Date().toTimeString().split(' ')[0];
    item.innerHTML = `
      <span class="log-time">[${time}]</span>
      <span class="log-speaker">[${speaker}]</span>
      <span>${escapeHtml(text)}</span>
    `;
    agentConsoleBody.appendChild(item);
    agentConsoleBody.scrollTop = agentConsoleBody.scrollHeight;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
});
