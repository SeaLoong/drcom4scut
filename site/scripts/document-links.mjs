import path from 'node:path';

/** Keep the same destination when documents move from GitHub to the website. */
export function createUrlRewriter({ documents, assets, guiRef }) {
  return (value, kind, file) => {
    if (value.startsWith('#')) return value;
    if (/^https?:/i.test(value)) {
      const url = new URL(value);
      if (url.hostname.toLowerCase() === 'sealoong.github.io' && url.pathname.startsWith('/drcom4scut/')) {
        return url.pathname.slice('/drcom4scut'.length) + url.search + url.hash;
      }
      if (url.hostname.toLowerCase() !== 'github.com') return value;
      const match = url.pathname.match(/^\/SeaLoong\/(drcom4scutGUI|drcom4scut)(?:\/(?:blob|tree)\/([^/]+)\/(.*))?$/);
      if (!match) return value;
      const other = match[1] === 'drcom4scutGUI' ? 'gui' : 'core';
      // Historical source references retain their original commit and meaning.
      if (match[2] && match[2] !== 'master' && !(other === 'gui' && match[2] === guiRef)) return value;
      const source = decodeURIComponent(match[3] || 'README.md');
      const target = documents.get(`${other}/${source}`) || assets.get(`${other}/${source}`);
      return target ? target + url.search + (url.hash === '#readme' ? '' : url.hash) : value;
    }
    if (/^(?:[a-z]+:|\/)/i.test(value)) return value;
    const url = new URL(value, `https://documents.invalid/${file}`);
    const resolved = decodeURIComponent(url.pathname.slice(1));
    const target = documents.get(`${kind}/${resolved}`) || assets.get(`${kind}/${resolved}`);
    if (target) return target + url.search + url.hash;
    const repository = kind === 'gui' ? 'drcom4scutGUI' : 'drcom4scut';
    const revision = kind === 'gui' ? guiRef : 'master';
    return `https://github.com/SeaLoong/${repository}/blob/${revision}/${resolved.split('/').map(encodeURIComponent).join('/')}${url.search}${url.hash}`;
  };
}

export function transformMarkdown(text, kind, file, rewriteUrl) {
  let fence = null;
  return text.split('\n').map(line => {
    const marker = line.match(/^\s*(`{3,}|~{3,})(.*)$/);
    if (marker && !fence) { fence = marker[1]; return line; }
    if (fence) {
      if (marker && marker[1][0] === fence[0] && marker[1].length >= fence.length && !marker[2].trim()) fence = null;
      return line;
    }
    // CI badges belong on the repository page. The site has its own navigation.
    if (path.posix.basename(file) === 'README.md' && /^\[!\[/.test(line.trim())) return '';
    const rewritten = line.replace(/(\]\()(<[^>]+>|[^\s)]+)(\))/g, (_, start, raw, end) => {
      const wrapped = raw.startsWith('<');
      const url = rewriteUrl(wrapped ? raw.slice(1, -1) : raw, kind, file);
      return start + (wrapped ? `<${url}>` : url) + end;
    });
    const referenced = rewritten.replace(/^(\s*\[[^\]]+\]:\s*)(<[^>]+>|\S+)/, (_, start, raw) => {
      const wrapped = raw.startsWith('<');
      const url = rewriteUrl(wrapped ? raw.slice(1, -1) : raw, kind, file);
      return start + (wrapped ? `<${url}>` : url);
    });
    const image = referenced.match(/^\s*(!\[[^\]]*\]\((<[^>]+>|[^\s)]+)\))\s*$/);
    if (image && image[2].replace(/^</, '').startsWith('/images/')) {
      return `[${image[1]}](${image[2]})\n\n[查看原图](${image[2]})`;
    }
    return referenced;
  }).join('\n');
}
