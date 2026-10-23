import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createUrlRewriter, transformMarkdown } from './document-links.mjs';

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
for (const name of (await fs.readdir(path.join(core, 'docs'))).filter(x => x.endsWith('.md')).sort()) entries.push(['core',`docs/${name}`,`guide/${name}`]);
for (const name of (await fs.readdir(path.join(gui, 'docs'))).filter(x => x.endsWith('.md')).sort()) entries.push(['gui',`docs/${name}`,`gui/${name}`]);
const mapped = new Map(entries.map(([kind, file, target]) => [`${kind}/${file}`,`/${target.replace(/\.md$/, '')}`]));
await fs.rm(out, { recursive: true, force: true });
await fs.mkdir(out, { recursive: true });

const assets = new Map();
const copiedAssets = [];
async function collectAssets(kind, relative, webRoot) {
  const directory = path.join(roots[kind], relative);
  let files;
  try { files = await fs.readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  for (const file of files.sort((a, b) => a.name.localeCompare(b.name))) {
    const source = path.posix.join(relative, file.name);
    const target = webRoot + '/' + file.name;
    if (file.isDirectory()) await collectAssets(kind, source, target);
    else if (file.isFile() && /\.(?:png|jpe?g|webp|gif|svg)$/i.test(file.name)) {
      assets.set(`${kind}/${source}`, target.split('/').map(encodeURIComponent).join('/'));
      copiedAssets.push([path.join(roots[kind], source), target]);
    } else if (file.isSymbolicLink()) throw new Error(`Document assets must be regular files: ${source}`);
  }
}
for (const kind of ['core', 'gui']) {
  await collectAssets(kind, 'docs/badges', `/badges/${kind}`);
  await collectAssets(kind, 'docs/images', `/images/${kind}`);
}
const rewriteUrl = createUrlRewriter({ documents: mapped, assets, guiRef: sources.gui.ref });

for (const [kind, file, target] of entries) {
  const text = transformMarkdown(await fs.readFile(path.join(roots[kind], file), 'utf8'), kind, file, rewriteUrl);
  const dest = path.join(out, target);
  await fs.mkdir(path.dirname(dest), { recursive: true });
  await fs.writeFile(dest, text);
}
await fs.cp(path.join(site,'pages'),out,{recursive:true});
await fs.cp(path.join(site,'public'),path.join(out,'public'),{recursive:true});
for (const [source, target] of copiedAssets) {
  const destination = path.join(out, 'public', target);
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.copyFile(source, destination);
}

const screenshots = [];
for (const kind of ['core', 'gui']) {
  let records;
  try { records = JSON.parse(await fs.readFile(path.join(roots[kind], 'docs/images/screenshots.json'), 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') continue; throw error; }
  if (!Array.isArray(records)) throw new Error('Screenshot metadata must be an array.');
  for (const record of records) {
    const image = assets.get(`${kind}/docs/images/${record.file}`);
    if (!image || !['Windows', 'macOS', 'Linux', 'OpenWrt'].includes(record.platform) || !['GUI', 'CLI', 'LuCI'].includes(record.kind)) {
      throw new Error(`Screenshot metadata must identify an existing image and its platform: ${record.file}`);
    }
    for (const field of ['title', 'description', 'version', 'capture']) {
      if (typeof record[field] !== 'string' || !record[field].trim()) throw new Error(`Missing screenshot ${field}: ${record.file}`);
    }
    screenshots.push({ ...record, image, repository: kind });
  }
}
const escapeText = text => text.replace(/[\\`*_{}[\]()<>#!|]/g, '\\$&').replace(/\r?\n/g, ' ');
let gallery = '# 运行截图\n\n查看客户端的实际界面和终端操作，再跟着对应平台的安装说明开始使用。\n\n';
gallery += '[Windows 图形界面](/gui/windows) · [Mac 图形界面](/gui/macos) · [Linux 图形界面](/gui/linux) · [命令行入门](/guide/getting-started)\n\n';
for (const platform of ['Windows', 'macOS', 'Linux', 'OpenWrt']) {
  const records = screenshots.filter(record => record.platform === platform);
  if (!records.length) continue;
  gallery += `## ${platform}\n\n`;
  for (const record of records) {
    gallery += `### ${record.kind === 'GUI' ? '图形界面' : record.kind === 'CLI' ? '命令行' : '路由器管理页'}：${escapeText(record.title)}\n\n`;
    const caption = record.kind === 'GUI'
      ? `实际 ${platform} 窗口，${record.mock_update_availability ? '更新版本号为演示数据' : '使用示例账号展示连接设置'}。`
      : record.description;
    gallery += `${escapeText(caption)}\n\n[![${escapeText(platform + ' ' + record.title)}](${record.image})](${record.image})\n\n[查看原图](${record.image})\n\n`;
    gallery += `<details>\n<summary>截图来源与版本</summary>\n\n版本：${escapeText(record.version)}。${escapeText(record.capture)}\n\n</details>\n\n`;
  }
}
await fs.writeFile(path.join(out, 'screenshots.md'), gallery);
const screenshotJson = JSON.stringify(screenshots, null, 2) + '\n';
await fs.writeFile(path.join(out, 'public/screenshots.json'), screenshotJson);
// This local data module is imported at build time by the homepage preview.
await fs.writeFile(path.join(out, 'screenshots-data.json'), screenshotJson);
console.log(`Prepared ${entries.length} source documents plus the website pages.`);
