/**
 * PRISM NETWORK - SECURE ACCESS PORTAL APP
 */
let pendingVerificationToken = null;
let sessionPollingTimer = null;

document.addEventListener('DOMContentLoaded', function() {
  setupNavigation();
  setupLoginForm();
  setupVerificationForm();
  setupResourceHandlers();
  setupSessionTerminationHandler();

  if (window.location.pathname === '/session-terminated') {
    showView('terminated');
  } else if (window.api && window.api.isAuthenticated()) {
    initAuthenticatedSession();
  } else {
    showView('login');
  }
});

function showView(viewName) {
  var views = ['login', 'verification', 'terminated', 'dashboard', 'resources', 'alerts'];
  for (var i = 0; i < views.length; i++) {
    var v = views[i];
    var el = document.getElementById('view-' + v);
    if (el) {
      if (v === viewName) {
        el.classList.add('active-view');
      } else {
        el.classList.remove('active-view');
      }
    }
  }

  var nav = document.getElementById('portal-nav');
  if (nav) {
    if (viewName === 'login' || viewName === 'verification' || viewName === 'terminated') {
      nav.style.display = 'none';
    } else {
      nav.style.display = 'flex';
      var links = document.querySelectorAll('.nav-link');
      for (var j = 0; j < links.length; j++) {
        var link = links[j];
        if (link.getAttribute('data-view') === viewName) {
          link.classList.add('active');
        } else {
          link.classList.remove('active');
        }
      }
    }
  }
}

function setupNavigation() {
  var links = document.querySelectorAll('.nav-link');
  for (var i = 0; i < links.length; i++) {
    (function(link) {
      link.addEventListener('click', function(e) {
        e.preventDefault();
        var targetView = link.getAttribute('data-view');
        showView(targetView);
        if (targetView === 'dashboard') loadDashboardData();
        if (targetView === 'resources') loadResourcesData();
        if (targetView === 'alerts') loadAlertsData();
      });
    })(links[i]);
  }

  var btnLogout = document.getElementById('btn-logout');
  if (btnLogout) {
    btnLogout.addEventListener('click', function() {
      if (window.api && window.api.currentSession) {
        window.api.terminateSession(window.api.currentSession.id).catch(function() {});
      }
      if (window.api) window.api.clearAuth();
      if (sessionPollingTimer) clearInterval(sessionPollingTimer);
      showView('login');
    });
  }

  var btnReturnLogin = document.getElementById('btn-return-login');
  if (btnReturnLogin) {
    btnReturnLogin.addEventListener('click', function() {
      if (window.api) window.api.clearAuth();
      window.history.pushState({}, '', '/');
      showView('login');
    });
  }

  var btnRefresh = document.getElementById('btn-refresh-activities');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', function() {
      loadDashboardData();
    });
  }
}

function setupLoginForm() {
  var form = document.getElementById('login-form');
  var errorBanner = document.getElementById('login-error-banner');
  var errorText = document.getElementById('login-error-text');
  var successBanner = document.getElementById('login-success-banner');
  var submitBtn = document.getElementById('btn-submit-login');

  var scenarioSelect = document.getElementById('demo-scenario');
  var locationSelect = document.getElementById('demo-location');
  var deviceSelect = document.getElementById('demo-device');

  if (scenarioSelect && locationSelect && deviceSelect) {
    scenarioSelect.addEventListener('change', function() {
      if (scenarioSelect.value === 'normal') {
        locationSelect.value = 'Chennai Office';
        deviceSelect.value = 'known';
      } else if (scenarioSelect.value === 'suspicious') {
        locationSelect.value = 'Remote';
        deviceSelect.value = 'new_device';
      } else if (scenarioSelect.value === 'critical') {
        locationSelect.value = 'Remote';
        deviceSelect.value = 'new_device';
      }
    });
  }

  if (!form) return;

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    errorBanner.style.display = 'none';
    successBanner.style.display = 'none';
    submitBtn.disabled = true;

    var username = document.getElementById('username').value.trim();
    var password = document.getElementById('password').value;
    var location = locationSelect ? locationSelect.value : 'Chennai Office';
    var deviceType = deviceSelect ? deviceSelect.value : 'known';
    var scenario = scenarioSelect ? scenarioSelect.value : 'normal';

    try {
      var extraHeaders = {};
      if (scenario === 'critical') {
        extraHeaders['x-simulated-hour'] = '23';
      }

      var resp = await window.api.request('/auth/login', {
        method: 'POST',
        headers: extraHeaders,
        body: JSON.stringify({
          username: username,
          password: password,
          demo_location: location,
          demo_device_type: deviceType
        })
      });

      if (!resp.ok) {
        errorText.textContent = (resp.data && resp.data.detail) ? resp.data.detail : 'Authentication failed.';
        errorBanner.style.display = 'flex';
        submitBtn.disabled = false;
        return;
      }

      var decisionData = resp.data;
      localStorage.setItem('prism_demo_location', location);
      localStorage.setItem('prism_demo_device', deviceType === 'new_device' ? 'New Unrecognized Device' : 'Known Managed Device');

      if (decisionData.decision === 'ALLOW') {
        successBanner.style.display = 'flex';
        window.api.setAuth(decisionData);
        setTimeout(function() {
          initAuthenticatedSession();
        }, 500);
      } else if (decisionData.decision === 'VERIFICATION_REQUIRED') {
        pendingVerificationToken = decisionData.verification_token;
        var reasonsList = document.getElementById('verification-reasons');
        reasonsList.innerHTML = '';
        var reasons = decisionData.detected_reasons || [];
        for (var k = 0; k < reasons.length; k++) {
          var li = document.createElement('li');
          li.textContent = reasons[k];
          reasonsList.appendChild(li);
        }
        showView('verification');
      } else if (decisionData.decision === 'CRITICAL') {
        window.api.clearAuth();
        var summary = document.getElementById('terminated-reasons-summary');
        if (summary && decisionData.detected_reasons) {
          summary.textContent = decisionData.detected_reasons.join(', ') + ' - Critical composite risk threshold breached.';
        }
        window.history.pushState({}, '', '/session-terminated');
        showView('terminated');
      }
    } catch (err) {
      errorText.textContent = err.message || 'Connection to gateway failed.';
      errorBanner.style.display = 'flex';
    } finally {
      submitBtn.disabled = false;
    }
  });
}

function setupVerificationForm() {
  var form = document.getElementById('verification-form');
  var btnCancel = document.getElementById('btn-cancel-verify');

  if (!form) return;

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    var code = document.getElementById('verify-code').value.trim();

    try {
      var resp = await window.api.verify(pendingVerificationToken, code);
      if (!resp.ok) {
        alert((resp.data && resp.data.detail) ? resp.data.detail : 'Verification code invalid.');
        return;
      }

      window.api.setAuth(resp.data);
      initAuthenticatedSession();
    } catch (err) {
      alert('Verification failed: ' + err.message);
    }
  });

  if (btnCancel) {
    btnCancel.addEventListener('click', function() {
      pendingVerificationToken = null;
      showView('login');
    });
  }
}

function initAuthenticatedSession() {
  var user = window.api.currentUser;
  if (!user) return showView('login');

  var navUsername = document.getElementById('nav-username');
  if (navUsername) navUsername.textContent = user.username;
  
  var roleBadge = document.getElementById('nav-role');
  if (roleBadge) {
    roleBadge.textContent = user.role.toUpperCase();
    var roleClass = (user.role === 'admin') ? 'badge-confidential' : ((user.role === 'senior_dev') ? 'badge-public' : 'badge-internal');
    roleBadge.className = 'badge-tag ' + roleClass;
  }

  showView('dashboard');
  loadDashboardData();

  if (sessionPollingTimer) clearInterval(sessionPollingTimer);
  sessionPollingTimer = setInterval(pollSessionHealth, 4000);
}

async function pollSessionHealth() {
  if (!window.api || !window.api.isAuthenticated() || !window.api.currentSession) return;

  try {
    var resp = await window.api.getSessionStatus(window.api.currentSession.id);
    if (!resp.ok || resp.data.status === 'terminated' || resp.data.risk_score >= 80.0) {
      window.api.clearAuth();
      if (sessionPollingTimer) clearInterval(sessionPollingTimer);
      window.history.pushState({}, '', '/session-terminated');
      showView('terminated');
    } else {
      updateRiskIndicator(resp.data.risk_score, resp.data.status);
    }
  } catch (err) {}
}

function updateRiskIndicator(score, status) {
  var indicator = document.getElementById('portal-risk-indicator');
  var statScore = document.getElementById('stat-risk-score');
  var statLevel = document.getElementById('stat-risk-level');
  var statStatus = document.getElementById('stat-session-status');

  if (statScore) statScore.textContent = score.toFixed(1) + ' / 100';

  var riskTier = 'LOW';
  var pillClass = 'risk-low';

  if (score >= 80.0) {
    riskTier = 'CRITICAL';
    pillClass = 'risk-critical';
  } else if (score >= 65.0) {
    riskTier = 'HIGH';
    pillClass = 'risk-high';
  } else if (score >= 45.0) {
    riskTier = 'MEDIUM';
    pillClass = 'risk-medium';
  }

  if (indicator) {
    indicator.className = 'risk-pill ' + pillClass;
    indicator.textContent = 'Status: ' + status.toUpperCase() + ' * ' + score.toFixed(1) + '/100 ' + riskTier;
  }
  if (statLevel) statLevel.textContent = 'Anomaly Tier: ' + riskTier;
  if (statStatus) statStatus.textContent = status.toUpperCase();
}

function setupSessionTerminationHandler() {
  window.addEventListener('prism:session-terminated', function() {
    if (sessionPollingTimer) clearInterval(sessionPollingTimer);
    window.history.pushState({}, '', '/session-terminated');
    showView('terminated');
  });
}

async function loadDashboardData() {
  if (!window.api || !window.api.currentSession) return;

  var loc = localStorage.getItem('prism_demo_location') || 'Chennai Office';
  var dev = localStorage.getItem('prism_demo_device') || 'Known Managed Device';
  var locEl = document.getElementById('stat-context-location');
  if (locEl) locEl.textContent = loc;
  var timeEl = document.getElementById('stat-context-time');
  if (timeEl) timeEl.textContent = 'Device: ' + dev;

  var sResp = await window.api.getSessionStatus(window.api.currentSession.id);
  if (sResp.ok) {
    updateRiskIndicator(sResp.data.risk_score, sResp.data.status);
    var devEl = document.getElementById('stat-session-device');
    if (devEl) devEl.textContent = 'Fingerprint: ' + sResp.data.device_fingerprint.substring(0, 16) + '...';
  }

  var actResp = await window.api.getActivities();
  var tableBody = document.getElementById('table-activities-body');
  if (tableBody) {
    tableBody.innerHTML = '';

    if (actResp.ok && actResp.data && actResp.data.length > 0) {
      for (var i = 0; i < Math.min(actResp.data.length, 12); i++) {
        var log = actResp.data[i];
        var tr = document.createElement('tr');
        var timeStr = new Date(log.timestamp).toLocaleTimeString();
        var statusClass = log.allowed ? 'color: #34d399;' : 'color: #f87171; font-weight: 700;';
        var statusText = log.allowed ? ('ALLOWED (' + log.status_code + ')') : ('DENIED (' + log.status_code + ')');
        var sens = log.resource_sensitivity || 'internal';

        tr.innerHTML = '<td>' + timeStr + '</td>' +
          '<td><code>' + log.endpoint + '</code></td>' +
          '<td><span class=\"badge-tag badge-public\">' + log.action.toUpperCase() + '</span></td>' +
          '<td><span class=\"badge-tag badge-' + sens + '\">' + sens.toUpperCase() + '</span></td>' +
          '<td style=\"' + statusClass + '\">' + statusText + '</td>' +
          '<td><code style=\"font-size: 0.75rem;\">' + (log.device_fingerprint || 'unknown').substring(0, 12) + '...</code></td>';
        tableBody.appendChild(tr);
      }
    } else {
      tableBody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align: center; color: #64748b;\">No activity records found or restricted by RBAC.</td></tr>';
    }
  }

  var alResp = await window.api.getAlerts(window.api.currentSession.id).catch(function() { return { ok: false }; });
  var alCountEl = document.getElementById('stat-active-alerts');
  if (alCountEl) {
    alCountEl.textContent = (alResp && alResp.ok && Array.isArray(alResp.data)) ? alResp.data.length : '0';
  }
}

function setupResourceHandlers() {
  var filterBtns = document.querySelectorAll('.filter-res-btn');
  for (var i = 0; i < filterBtns.length; i++) {
    (function(btn) {
      btn.addEventListener('click', function() {
        var filter = btn.getAttribute('data-filter');
        loadResourcesData(filter === 'all' ? null : filter);
      });
    })(filterBtns[i]);
  }

  var modal = document.getElementById('resource-denied-modal');
  var closeBtn = document.getElementById('btn-close-denied-modal');
  if (closeBtn && modal) {
    closeBtn.addEventListener('click', function() {
      modal.classList.remove('active');
    });
  }

  var bulkBtn = document.getElementById('btn-trigger-bulk-exfil');
  if (bulkBtn) {
    bulkBtn.addEventListener('click', async function() {
      bulkBtn.disabled = true;
      bulkBtn.textContent = 'Executing Bulk Downloads...';

      var resResp = await window.api.getResources('confidential');
      if (resResp.ok && resResp.data && resResp.data.length > 0) {
        for (var j = 0; j < Math.min(resResp.data.length, 18); j++) {
          await window.api.downloadResource(resResp.data[j].id).catch(function() {});
        }
      }

      bulkBtn.disabled = false;
      bulkBtn.textContent = 'Simulate Rapid Bulk Downloads';
      await pollSessionHealth();
      loadDashboardData();
    });
  }
}

async function loadResourcesData(sensitivity) {
  var tableBody = document.getElementById('table-resources-body');
  if (!tableBody) return;
  tableBody.innerHTML = '<tr><td colspan=\"5\" style=\"text-align: center; color: #64748b;\">Loading resources...</td></tr>';

  var resp = await window.api.getResources(sensitivity);
  if (!resp.ok) {
    tableBody.innerHTML = '<tr><td colspan=\"5\" style=\"text-align: center; color: #f87171;\">Failed to load resources: ' + (resp.data.detail || 'Access error') + '</td></tr>';
    return;
  }

  tableBody.innerHTML = '';
  for (var i = 0; i < Math.min(resp.data.length, 25); i++) {
    var res = resp.data[i];
    var tr = document.createElement('tr');
    tr.innerHTML = '<td>' + res.id + '</td>' +
      '<td><strong>' + res.name + '</strong></td>' +
      '<td><span class=\"badge-tag badge-' + res.sensitivity + '\">' + res.sensitivity.toUpperCase() + '</span></td>' +
      '<td>' + (res.description || 'Enterprise documentation asset') + '</td>' +
      '<td>' +
        '<button class=\"btn-sm btn-read-res\" data-id=\"' + res.id + '\">Read</button>' +
        '<button class=\"btn-sm btn-dl-res\" data-id=\"' + res.id + '\" style=\"margin-left: 4px;\">Download</button>' +
      '</td>';
    tableBody.appendChild(tr);
  }

  var readBtns = document.querySelectorAll('.btn-read-res');
  for (var r = 0; r < readBtns.length; r++) {
    (function(b) {
      b.addEventListener('click', function() {
        handleResourceAction(b.getAttribute('data-id'), 'read');
      });
    })(readBtns[r]);
  }

  var dlBtns = document.querySelectorAll('.btn-dl-res');
  for (var d = 0; d < dlBtns.length; d++) {
    (function(b) {
      b.addEventListener('click', function() {
        handleResourceAction(b.getAttribute('data-id'), 'download');
      });
    })(dlBtns[d]);
  }
}

async function handleResourceAction(id, action) {
  try {
    var resp = (action === 'download') 
      ? await window.api.downloadResource(id)
      : await window.api.getResourceDetail(id);

    if (resp.status === 403) {
      var modal = document.getElementById('resource-denied-modal');
      var msg = document.getElementById('resource-denied-message');
      if (msg) msg.textContent = resp.data.detail || 'Permission denied: Your current role is not authorized to access this confidential resource.';
      if (modal) modal.classList.add('active');
    } else if (resp.ok) {
      alert('[ACCESS GRANTED: ' + action.toUpperCase() + ']\n\nResource: ' + resp.data.name + '\nSensitivity: ' + resp.data.sensitivity.toUpperCase() + '\nContent Verified.');
    }

    pollSessionHealth();
  } catch (err) {}
}

async function loadAlertsData() {
  var tableBody = document.getElementById('table-alerts-body');
  if (!tableBody) return;
  tableBody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align: center; color: #64748b;\">Loading alerts...</td></tr>';

  var resp = await window.api.getAlerts();
  if (!resp.ok) {
    tableBody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align: center; color: #f87171;\">Access Restricted: ' + (resp.data.detail || 'Interns cannot view security alerts.') + '</td></tr>';
    return;
  }

  tableBody.innerHTML = '';
  if (!resp.data || resp.data.length === 0) {
    tableBody.innerHTML = '<tr><td colspan=\"6\" style=\"text-align: center; color: #64748b;\">No security anomalies flagged for this session.</td></tr>';
    return;
  }

  for (var i = 0; i < resp.data.length; i++) {
    var alertItem = resp.data[i];
    var tr = document.createElement('tr');
    var signals = (alertItem.evidence && alertItem.evidence.evidence_signals) ? alertItem.evidence.evidence_signals.join('; ') : alertItem.alert_type;

    tr.innerHTML = '<td><span class=\"risk-pill risk-' + alertItem.severity + '\">' + alertItem.severity.toUpperCase() + '</span></td>' +
      '<td><strong>' + alertItem.risk_score.toFixed(1) + '/100</strong></td>' +
      '<td><strong>' + alertItem.title + '</strong></td>' +
      '<td style=\"font-size: 0.8125rem; max-width: 320px;\">' + signals + '</td>' +
      '<td style=\"color: #60a5fa; font-size: 0.8125rem;\">' + alertItem.recommended_action + '</td>' +
      '<td><span class=\"badge-tag badge-internal\">' + alertItem.status.toUpperCase() + '</span></td>';
    tableBody.appendChild(tr);
  }
}