/**
 * PRISM NETWORK - API CLIENT
 * Direct communication with FastAPI backend
 */

var API_BASE = '/api/v1';

function PrismApiClient() {
  this.token = localStorage.getItem('prism_access_token');
  try {
    this.currentUser = JSON.parse(localStorage.getItem('prism_user') || 'null');
    this.currentSession = JSON.parse(localStorage.getItem('prism_session') || 'null');
  } catch (e) {
    this.currentUser = null;
    this.currentSession = null;
  }
}

PrismApiClient.prototype.setAuth = function(tokenData) {
  this.token = tokenData.access_token;
  localStorage.setItem('prism_access_token', this.token);
  
  this.currentUser = {
    id: tokenData.user_id,
    username: tokenData.username,
    role: tokenData.role
  };
  localStorage.setItem('prism_user', JSON.stringify(this.currentUser));

  this.currentSession = {
    id: tokenData.session_id,
    token_id: tokenData.session_token_id,
    device_fingerprint: tokenData.device_fingerprint,
    risk_score: tokenData.risk_score || 0
  };
  localStorage.setItem('prism_session', JSON.stringify(this.currentSession));
};

PrismApiClient.prototype.clearAuth = function() {
  this.token = null;
  this.currentUser = null;
  this.currentSession = null;
  localStorage.removeItem('prism_access_token');
  localStorage.removeItem('prism_user');
  localStorage.removeItem('prism_session');
};

PrismApiClient.prototype.isAuthenticated = function() {
  return !!this.token;
};

PrismApiClient.prototype.request = async function(endpoint, options) {
  options = options || {};
  var url = API_BASE + endpoint;
  var headers = {
    'Content-Type': 'application/json'
  };

  if (options.headers) {
    for (var key in options.headers) {
      if (options.headers.hasOwnProperty(key)) {
        headers[key] = options.headers[key];
      }
    }
  }

  if (this.token) {
    headers['Authorization'] = 'Bearer ' + this.token;
  }

  var fetchOpts = {
    method: options.method || 'GET',
    headers: headers
  };

  if (options.body) {
    fetchOpts.body = options.body;
  }

  try {
    var response = await fetch(url, fetchOpts);

    if (response.status === 401 && endpoint.indexOf('/auth/login') === -1) {
      this.clearAuth();
      window.dispatchEvent(new CustomEvent('prism:session-terminated', { 
        detail: { reason: 'Session expired or revoked by security policy' } 
      }));
      throw new Error('Session has been terminated. Please re-authenticate.');
    }

    var data = {};
    try {
      data = await response.json();
    } catch (parseErr) {
      data = {};
    }

    return {
      ok: response.ok,
      status: response.status,
      data: data
    };
  } catch (err) {
    console.error('API Error [' + endpoint + ']:', err);
    throw err;
  }
};

PrismApiClient.prototype.login = async function(username, password, demoLocation, demoDeviceType) {
  return this.request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      username: username,
      password: password,
      demo_location: demoLocation,
      demo_device_type: demoDeviceType
    })
  });
};

PrismApiClient.prototype.verify = async function(verificationToken, code) {
  return this.request('/auth/verify', {
    method: 'POST',
    body: JSON.stringify({
      verification_token: verificationToken,
      code: code
    })
  });
};

PrismApiClient.prototype.getMe = async function() {
  return this.request('/auth/me');
};

PrismApiClient.prototype.getResources = async function(sensitivity) {
  var url = '/resources';
  if (sensitivity) {
    url += '?sensitivity=' + sensitivity;
  }
  return this.request(url);
};

PrismApiClient.prototype.getResourceDetail = async function(id) {
  return this.request('/resources/' + id);
};

PrismApiClient.prototype.downloadResource = async function(id) {
  return this.request('/resources/' + id + '/download');
};

PrismApiClient.prototype.getSessionStatus = async function(sessionId) {
  return this.request('/sessions/' + sessionId);
};

PrismApiClient.prototype.terminateSession = async function(sessionId) {
  return this.request('/sessions/' + sessionId + '/terminate', { method: 'POST' });
};

PrismApiClient.prototype.getAlerts = async function(sessionId) {
  var url = '/alerts';
  if (sessionId) {
    url += '?session_id=' + sessionId;
  }
  return this.request(url);
};

PrismApiClient.prototype.getActivities = async function() {
  return this.request('/activities?limit=25');
};

window.api = new PrismApiClient();
console.log('[Prism Portal] window.api initialized successfully.');