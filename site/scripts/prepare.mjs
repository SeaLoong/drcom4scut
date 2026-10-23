import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const site = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const core = path.dirname(site);
const gui = process.env.GUI_DOCS_DIR ? path.resolve(process.env.GUI_DOCS_DIR) : path.resolve(core, '../drcom4scutGUI');
const out = path.join(site, 'content');
const sources = JSON.parse(await fs.readFile(path.join(site, 'sources.json'), 'utf8'));
if (sources.gui.repository !== 'SeaLoong/drcom4scutGUI' || !/^[a-f0-9]{40}$/.test(sources.gui.ref)) {
  throw new Error('sources.json must name the GUI repository and a full commit SHA.');
}
const roots = { core, gui };
const entries = [
  ['core','README.md','overview.md'],
  ['core','CHANGELOG.md','changes.md'],
  ['core','SECURITY.md','security.md'],
  ['core','packaging/openwrt/luci-app-drcom4scut/README.md','guide/luci.md'],
  ['gui','README.md','desktop.md'],
  ['gui','THIRD-PARTY-NOTICES.md','gui/notices.md'],
  ['gui','SECURITY.md','gui/security-policy.md'],
];
for (const name of (await fs.readdir(path.join(core, 'docs'))).filter(x => x.endsWith('.md'))) entries.push(['core',`docs/${name}`,`guide/${name}`]);
for (const name of (await fs.readdir(path.join(gui, 'docs'))).filter(x => x.endsWith('.md'))) entries.push(['gui',`docs/${name}`,`gui/${name}`]);
const mapped = new Map(entries.map(([kind, file, target]) => [`${kind}/${file}`,`/${target.replace(/\.md$/, '')}`]));
await fs.rm(out, { recursive: true, force: true });
await fs.mkdir(out, { recursive: true });

function rewriteUrl(url, kind, file) {
  if (url.startsWith('#') || url.startsWith('mailto:')) return url;
  if (url.startsWith('https://SeaLoong.github.io/drcom4scut/') || url.startsWith('https://sealoong.github.io/drcom4scut/')) return '/';
  const github = url.match(/^https:\/\/github\.com\/SeaLoong\/(drcom4scutGUI|drcom4scut)(?:\/(?:blob|tree)\/(?:master|[a-f0-9]{40})\/(.*?))?(#[^?]*)?$/);
  if (github) {
    const other = github[1] === 'drcom4scutGUI' ? 'gui' : 'core';
    const source = github[2] || 'README.md';
    const target = mapped.get(`${other}/${source}`);
    if (target) return target + (github[3] && github[3] !== '#readme' ? github[3] : '');
  }
  if (/^(?:[a-z]+:|\/)/i.test(url)) return url;
  const [raw, anchor = ''] = url.split('#');
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), raw));
  const target = mapped.get(`${kind}/${resolved}`);
  if (target) return target + (anchor ? '#' + anchor : '');
  if (resolved.startsWith('docs/badges/')) return `/badges/${kind}/${path.posix.basename(resolved)}`;
  return `https://github.com/SeaLoong/${kind === 'gui' ? 'drcom4scutGUI' : 'drcom4scut'}/blob/${kind === 'gui' ? sources.gui.ref : 'master'}/${resolved}${anchor ? '#' + anchor : ''}`;
}

for (const [kind, file, target] of entries) {
  let text = await fs.readFile(path.join(roots[kind], file), 'utf8');
  // Transform only Markdown links outside fenced code; examples remain byte-for-byte.
  let fence = null;
  text = text.split('\n').map(line => {
    const marker = line.match(/^\s*(`{3,}|~{3,})/);
    if (marker) { if (!fence) fence = marker[1][0]; else if (fence === marker[1][0]) fence = null; return line; }
    if (fence) return line;
    return line.replace(/(\]\()([^\s)]+)(\))/g, (_,a,url,z) => a + rewriteUrl(url, kind, file) + z);
  }).join('\n');
  const dest = path.join(out, target);
  await fs.mkdir(path.dirname(dest), { recursive: true });
  await fs.writeFile(dest, text);
}
await fs.cp(path.join(site,'pages'),out,{recursive:true});
await fs.cp(path.join(site,'public'),path.join(out,'public'),{recursive:true});
for (const kind of ['core','gui']) await fs.cp(path.join(roots[kind],'docs/badges'),path.join(out,'public/badges',kind),{recursive:true});
console.log(`Prepared ${entries.length} source documents plus the website pages.`);
