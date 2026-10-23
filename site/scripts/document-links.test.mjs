import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createUrlRewriter, transformMarkdown } from './document-links.mjs';

const guiRef = 'a'.repeat(40);
const documents = new Map([
  ['core/README.md', '/overview'], ['gui/README.md', '/desktop'],
  ['core/docs/download.md', '/guide/download'], ['gui/docs/windows.md', '/gui/windows'],
]);
const assets = new Map([
  ['core/docs/images/linux-cli.png', '/images/core/linux-cli.png'],
  ['gui/docs/images/Mac window.png', '/images/gui/Mac%20window.png'],
]);
const rewrite = createUrlRewriter({ documents, assets, guiRef });

test('preserves site deep paths, query and fragments in absolute links', () => {
  assert.equal(rewrite('https://SeaLoong.github.io/drcom4scut/gui/windows?from=help#安装', 'core', 'README.md'), '/gui/windows?from=help#%E5%AE%89%E8%A3%85');
  assert.equal(rewrite('https://sealoong.github.io/drcom4scut/', 'gui', 'README.md'), '/');
});
test('maps relative and pinned GUI images to real copied image files', () => {
  assert.equal(rewrite('images/linux-cli.png', 'core', 'docs/linux.md'), '/images/core/linux-cli.png');
  assert.equal(rewrite('images/Mac%20window.png', 'gui', 'docs/macos.md'), '/images/gui/Mac%20window.png');
  assert.equal(rewrite(`https://github.com/SeaLoong/drcom4scutGUI/blob/${guiRef}/docs/images/Mac%20window.png`, 'core', 'README.md'), '/images/gui/Mac%20window.png');
});
test('maps current documents and preserves historical source references', () => {
  assert.equal(rewrite('../README.md#readme', 'core', 'docs/linux.md'), '/overview#readme');
  assert.equal(rewrite('download.md#选择', 'core', 'docs/linux.md'), '/guide/download#%E9%80%89%E6%8B%A9');
  const historical = `https://github.com/SeaLoong/drcom4scut/blob/${'b'.repeat(40)}/docs/download.md`;
  assert.equal(rewrite(historical, 'core', 'README.md'), historical);
  assert.equal(rewrite('https://github.com/SeaLoong/drcom4scutGUI#readme', 'core', 'README.md'), '/desktop');
});
test('removes README badge rows, preserving normal links and code examples', () => {
  const source = '[![CI](https://example.org/badge.svg)](https://example.org/checks)\n[Download](docs/download.md)\n````md\n```\n[example](docs/download.md)\n```\n````';
  assert.equal(transformMarkdown(source, 'core', 'README.md', rewrite), '\n[Download](/guide/download)\n````md\n```\n[example](docs/download.md)\n```\n````');
});
test('handles image paths with spaces and Markdown reference links', () => {
  const source = '![Mac](<images/Mac window.png>)\n[windows]: windows.md';
  assert.equal(transformMarkdown(source, 'gui', 'docs/macos.md', rewrite), '[![Mac](</images/gui/Mac%20window.png>)](</images/gui/Mac%20window.png>)\n\n[查看原图](</images/gui/Mac%20window.png>)\n[windows]: /gui/windows');
});
