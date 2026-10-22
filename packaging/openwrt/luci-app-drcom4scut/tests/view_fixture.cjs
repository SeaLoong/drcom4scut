// Execute the authored view against small LuCI API fixtures, not a fake browser.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(process.argv[2], 'utf8');
const options = [];
const calls = [];
const invocations = [];
const secret = 'fixture-private-account-password';
let downloaded;
const response = {
  status: { phase: 'online', running: true, version: '0.4.0', enabled: false },
  logs: { events: [] },
  diagnostics: {
    phase: 'online', running: true, online: true, eap_authenticated: true,
    version: '0.4.0', updated_at: '2026-10-23T12:30:00+08:00',
    username: secret, password: secret, local_ip: '192.0.2.5', interface: secret,
    events: [{ event: secret, level: secret, text: secret }, { event: 'udp-heartbeat', level: 'info' }, null]
  }
};
const rpc = { declare(definition) {
  calls.push([definition.object, definition.method]);
  return () => { invocations.push(definition.method); return Promise.resolve(response[definition.method] || { success: true }); };
} };
function Map() {}
Map.prototype.section = () => ({ option(type, name, label) {
  const option = { type, name, label }; options.push(option); return option;
} });
Map.prototype.render = () => Promise.resolve({ kind: 'form' });
const form = { Map, NamedSection: 'named', Flag: 'flag', Value: 'value' };
function E(tag, attributes, children) {
  return { tag, attributes, children, style: {}, click() {}, remove() {} };
}
const L = { bind: (fn, self, ...args) => fn.bind(self, ...args), hasViewPermission: () => true };
const UI = new Function('view', 'form', 'rpc', 'poll', 'dom', 'ui', 'uci', 'L', 'E', '_', 'Blob', 'URL', 'document', 'window', source)(
  { extend: value => value }, form, rpc, { add() {} }, { content() {} }, { addNotification() {} },
  { load: () => Promise.resolve() }, L, E, text => text, Blob,
  { createObjectURL(blob) { downloaded = blob; return 'blob:fixture'; }, revokeObjectURL() {} },
  { body: { appendChild() {} } }, { setTimeout(fn) { fn(); } }
);
(async function() {
  const data = await UI.load();
  await UI.render(data);
  assert.deepEqual(options.map(item => item.name), ['enabled', 'network', 'interface', 'config', 'password_file']);
  assert(!options.some(item => item.name === 'password' || item.type === 'password'));
  // A disabled persisted service stays disabled after merely checking Enable.
  assert.equal(UI.startButton.disabled, true);
  assert.equal(UI.restartButton.disabled, true);
  assert.equal(UI.stopButton.disabled, false);
  const enabledOption = options.find(item => item.name === 'enabled');
  enabledOption.onchange(null, 'main', '1');
  assert.equal(UI.startButton.disabled, true);
  await UI.runAction('start', {});
  await UI.runAction('restart', {});
  assert(!invocations.includes('start'));
  assert(!invocations.includes('restart'));
  // Only the authoritative saved UCI state arriving through status unlocks it.
  response.status.enabled = true;
  await UI.refresh();
  assert.equal(UI.startButton.disabled, false);
  assert.equal(UI.restartButton.disabled, false);
  enabledOption.onchange(null, 'main', '0');
  assert.equal(UI.startButton.disabled, true);
  assert.equal(UI.stopButton.disabled, false);
  enabledOption.onchange(null, 'main', '1');
  await UI.runAction('restart', {});
  assert.equal(invocations.filter(method => method === 'restart').length, 1);
  response.status.enabled = false;
  await UI.refresh();
  assert.equal(UI.startButton.disabled, true);
  await UI.runAction('stop', {});
  assert.equal(invocations.filter(method => method === 'stop').length, 1);
  assert.equal(UI.stopButton.disabled, false);

  for (const name of ['config', 'password_file']) {
    const option = options.find(item => item.name === name);
    assert.equal(option.validate('main', '/etc/drcom4scut/password'), true);
    for (const invalid of ['/etc/shadow', '/etc/drcom4scut/../shadow', '/etc/drcom4scut/sub/file', '/etc/drcom4scut/..', '/etc/drcom4scut/a;reboot'])
      assert.notEqual(option.validate('main', invalid), true, invalid);
  }
  assert(calls.every(([object]) => object === 'drcom4scut'));
  assert.deepEqual(new Set(calls.map(([, method]) => method)), new Set(['status', 'logs', 'diagnostics', 'start', 'stop', 'restart']));
  const log = UI.renderLogs({ events: [{ event: secret, level: secret, text: '<img src=x>' + secret }] });
  assert(!JSON.stringify(log).includes(secret));
  assert.doesNotThrow(() => UI.renderLogs({ events: [null, 3, {}] }));
  assert.doesNotThrow(() => UI.renderLogs(null));
  await UI.downloadDiagnostics();
  const text = await downloaded.text();
  assert(!text.includes(secret));
  assert(!text.includes('192.0.2.5'));
  const report = JSON.parse(text);
  assert.equal(report.credentials_included, false);
  assert.equal(report.events[0].event, 'message-redacted');
  assert.equal(report.events[1].event, 'udp-heartbeat');
  assert(!Object.hasOwn(report, 'password'));
  assert(!Object.hasOwn(report, 'interface'));
  console.log('LuCI view fixtures passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
