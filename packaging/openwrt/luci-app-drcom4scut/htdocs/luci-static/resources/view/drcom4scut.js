'use strict';
'require view';
'require form';
'require rpc';
'require poll';
'require dom';
'require ui';
'require uci';

var status = rpc.declare({ object: 'drcom4scut', method: 'status', expect: { '': {} } });
var logs = rpc.declare({ object: 'drcom4scut', method: 'logs', expect: { '': {} } });
var diagnostics = rpc.declare({ object: 'drcom4scut', method: 'diagnostics', expect: { '': {} } });
var actions = {
	start: rpc.declare({ object: 'drcom4scut', method: 'start', expect: { '': {} } }),
	stop: rpc.declare({ object: 'drcom4scut', method: 'stop', expect: { '': {} } }),
	restart: rpc.declare({ object: 'drcom4scut', method: 'restart', expect: { '': {} } })
};

var phases = {
	online: _('Online'),
	offline: _('Offline'),
	'waiting-interface': _('Waiting for Ethernet interface'),
	'eap-authentication': _('Authenticating Ethernet (802.1X)'),
	'udp-authentication': _('Starting DrCOM session'),
	unavailable: _('Status unavailable')
};
var events = {
	'eap-authenticated': _('Ethernet authentication succeeded'),
	'udp-heartbeat': _('UDP heartbeat completed'),
	'eap-timeout': _('Ethernet authentication or heartbeat timed out'),
	'udp-timeout': _('UDP response timed out'),
	'dns-error': _('DNS lookup failed'),
	shutdown: _('Client shutdown requested'),
	'transport-error': _('Network transport error'),
	'server-notice-redacted': _('Server notice (content omitted)'),
	'message-redacted': _('Client message (content omitted)')
};

function privatePath(value) {
	return /^\/etc\/drcom4scut\/[A-Za-z0-9_.-]+$/.test(value) &&
		value !== '/etc/drcom4scut/.' && value !== '/etc/drcom4scut/..';
}

function diagnosticReport(report) {
	report = report && typeof report === 'object' ? report : {};
	var version = typeof report.version === 'string' && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(report.version) ? report.version : 'unknown';
	var updated = typeof report.updated_at === 'string' && /^\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2})$/.test(report.updated_at) ? report.updated_at : '';
	return {
		schema: 1,
		version: version,
		phase: Object.prototype.hasOwnProperty.call(phases, report.phase) ? report.phase : 'unavailable',
		running: report.running === true,
		online: report.online === true,
		eap_authenticated: report.eap_authenticated === true,
		updated_at: updated,
		credentials_included: false,
		events: (Array.isArray(report.events) ? report.events.slice(-60) : []).map(function(entry) {
			entry = entry && typeof entry === 'object' ? entry : {};
			return {
				event: Object.prototype.hasOwnProperty.call(events, entry.event) ? entry.event : 'message-redacted',
				level: ['info', 'warning', 'error'].indexOf(entry.level) >= 0 ? entry.level : 'info'
			};
		})
	};
}

return view.extend({
	load: function() {
		return Promise.all([uci.load('drcom4scut'), status(), logs()]);
	},

	renderStatus: function(info) {
		var phase = Object.prototype.hasOwnProperty.call(phases, info.phase) ? phases[info.phase] : phases.unavailable;
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Connection status')),
			E('p', {}, [E('strong', {}, phase)]),
			E('p', {}, _('Service process: ') + (info.running ? _('Running') : _('Stopped'))),
			E('p', {}, _('Core version: ') + (info.version || _('Unknown'))),
			E('p', {}, _('Interface: ') + (info.interface || _('Unavailable'))),
			E('p', {}, _('Updated: ') + (info.updated_at || _('Unavailable')))
		]);
	},

	renderLogs: function(result) {
		result = result && typeof result === 'object' ? result : {};
		var rows = Array.isArray(result.events) ? result.events.slice(-60) : [];
		var body = rows.map(function(entry) {
			entry = entry && typeof entry === 'object' ? entry : {};
			var event = Object.prototype.hasOwnProperty.call(events, entry.event) ? events[entry.event] : events['message-redacted'];
			var level = ['info', 'warning', 'error'].indexOf(entry.level) >= 0 ? entry.level : 'info';
			return E('tr', {}, [E('td', {}, level), E('td', {}, event)]);
		});
		if (!body.length) body.push(E('tr', {}, [E('td', { colspan: 2 }, _('No recent events'))]));
		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Recent log events')),
			E('p', {}, _('Privacy-safe categories are shown. Server text and arbitrary message content stay on the router.')),
			E('table', { 'class': 'table' }, [
				E('tr', {}, [E('th', {}, _('Level')), E('th', {}, _('Event'))])
			].concat(body))
		]);
	},

	refresh: function() {
		return Promise.all([status(), logs()]).then(L.bind(function(result) {
			this.serviceEnabled = !!(result[0] && result[0].enabled === true);
			this.updateControls();
			dom.content(this.statusNode, this.renderStatus(result[0] || {}));
			dom.content(this.logNode, this.renderLogs(result[1] || {}));
		}, this));
	},

	updateControls: function() {
		var pending = this.requestedEnabled !== this.serviceEnabled;
		var permitted = L.hasViewPermission();
		var cannotStart = !permitted || !this.serviceEnabled || pending || this.actionPending;
		if (this.startButton) this.startButton.disabled = cannotStart;
		if (this.restartButton) this.restartButton.disabled = cannotStart;
		if (this.stopButton) this.stopButton.disabled = !permitted || this.actionPending;
		if (this.enableHint) this.enableHint.style.display = (!this.serviceEnabled || pending) ? '' : 'none';
	},

	runAction: function(method, event) {
		if (method !== 'stop' && (!this.serviceEnabled || this.requestedEnabled !== this.serviceEnabled))
			return Promise.resolve();
		this.actionPending = true;
		this.updateControls();
		return actions[method]().then(L.bind(function(result) {
			if (!result.success) {
				if (result.error === 'disabled') {
					this.serviceEnabled = false;
					ui.addNotification(null, E('p', {}, _('Enable the service and save and apply the settings before starting or reconnecting.')), 'warning');
					return this.refresh();
				}
				throw new Error('Service operation failed');
			}
			return this.refresh();
		}, this)).catch(function() {
			ui.addNotification(null, E('p', {}, _('The service operation failed. Check the private configuration and system log on the router.')), 'error');
		}).finally(L.bind(function() {
			this.actionPending = false;
			this.updateControls();
		}, this));
	},

	downloadDiagnostics: function() {
		return diagnostics().then(function(report) {
			// The RPC method already exports a closed metadata/event schema. Do not
			// include UCI, DOM contents, browser state, raw logs or credential files.
			var blob = new Blob([JSON.stringify(diagnosticReport(report), null, 2) + '\n'], { type: 'application/json' });
			var url = URL.createObjectURL(blob);
			var link = E('a', { href: url, download: 'drcom4scut-diagnostics.json' });
			document.body.appendChild(link);
			link.click();
			link.remove();
			window.setTimeout(function() { URL.revokeObjectURL(url); }, 0);
		}).catch(function() {
			ui.addNotification(null, E('p', {}, _('Unable to export diagnostics.')), 'error');
		});
	},

	render: function(data) {
		var map = new form.Map('drcom4scut', _('SCUT DrCOM'),
			_('Manage the dedicated client service. Maintain the password through SSH in a root-owned private file; this page only stores its path.'));
		var section = map.section(form.NamedSection, 'main', 'client', _('Service settings'));
		section.addremove = false;
		this.serviceEnabled = !!(data[1] && data[1].enabled === true);
		this.requestedEnabled = this.serviceEnabled;
		this.actionPending = false;
		var option = section.option(form.Flag, 'enabled', _('Enable service'));
		option.rmempty = false;
		option.onchange = L.bind(function(event, sectionId, value) {
			this.requestedEnabled = value === '1' || value === 1 || value === true;
			this.updateControls();
		}, this);
		option = section.option(form.Value, 'network', _('Logical network'));
		option.default = 'wan';
		option.rmempty = false;
		option.validate = function(sectionId, value) {
			return /^[A-Za-z0-9_]+$/.test(value) || _('Use a valid logical network name.');
		};
		option = section.option(form.Value, 'interface', _('Physical Ethernet device'));
		option.placeholder = _('Automatic from logical network');
		option.description = _('Leave empty to select the network layer-2 device before DHCP becomes available.');
		option.validate = function(sectionId, value) {
			return !value || (/^[A-Za-z0-9_.:@-]+$/.test(value) && value.length <= 32) || _('Use a valid Ethernet device name.');
		};
		option = section.option(form.Value, 'config', _('Private configuration path'));
		option.default = '/etc/drcom4scut/config.yml';
		option.rmempty = false;
		option.validate = function(sectionId, value) {
			return privatePath(value) || _('Use a direct file inside /etc/drcom4scut.');
		};
		option = section.option(form.Value, 'password_file', _('Private password file path'));
		option.default = '/etc/drcom4scut/password';
		option.rmempty = false;
		option.description = _('The file must be owned by root with mode 0400 or 0600. Its contents are never read by this page.');
		option.validate = function(sectionId, value) {
			return privatePath(value) || _('Use a direct file inside /etc/drcom4scut.');
		};

		this.statusNode = E('div', {}, this.renderStatus(data[1] || {}));
		this.logNode = E('div', {}, this.renderLogs(data[2] || {}));
		this.startButton = E('button', { 'class': 'cbi-button cbi-button-apply', type: 'button', click: L.bind(this.runAction, this, 'start') }, _('Start'));
		this.stopButton = E('button', { 'class': 'cbi-button cbi-button-reset', type: 'button', click: L.bind(this.runAction, this, 'stop') }, _('Stop'));
		this.restartButton = E('button', { 'class': 'cbi-button cbi-button-reload', type: 'button', click: L.bind(this.runAction, this, 'restart') }, _('Reconnect'));
		this.enableHint = E('p', {}, _('Enable the service and save and apply the settings before starting or reconnecting.'));
		var controls = E('div', { 'class': 'cbi-section' }, [
			this.enableHint, this.startButton, ' ', this.stopButton, ' ', this.restartButton,
			' ', E('button', { 'class': 'cbi-button cbi-button-action', type: 'button', click: L.bind(this.downloadDiagnostics, this) }, _('Export redacted diagnostics'))
		]);
		this.updateControls();
		poll.add(L.bind(function() { return this.refresh().catch(function() {}); }, this), 5);
		return map.render().then(L.bind(function(formNode) {
			return E('div', {}, [this.statusNode, controls, this.logNode, formNode]);
		}, this));
	}
});
