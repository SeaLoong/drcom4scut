"""Check rendered local links, images and fragments under the Pages base path."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import posixpath

root = Path(__file__).resolve().parents[1] / '.vitepress/dist'
base = '/drcom4scut/'

class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids, self.links = set(), []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs: self.ids.add(attrs['id'])
        for key in ('href', 'src'):
            if key in attrs: self.links.append(attrs[key])

pages = {}
for file in root.rglob('*.html'):
    p = Page(); p.feed(file.read_text()); pages[file.relative_to(root).as_posix()] = p
required = {'index.html', 'desktop.html', 'guide/download.html', 'guide/getting-started.html', 'gui/usage.html'}
missing = required.difference(pages)
if missing: raise SystemExit('Missing required pages: ' + ', '.join(sorted(missing)))
errors, count = [], 0
for file, page in pages.items():
    for link in page.links:
        url = urlsplit(link)
        if url.scheme or url.netloc or not link or link.startswith('data:'): continue
        target = unquote(url.path)
        if target.startswith('/'):
            if not target.startswith(base):
                errors.append(f'{file}: link outside Pages base: {link}'); continue
            target = target[len(base):]
        elif target:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(file), target))
        else: target = file
        if not target or target.endswith('/'): target += 'index.html'
        candidates = [target, target + '.html', target + '/index.html']
        actual = next((x for x in candidates if (root/x).is_file()), None)
        if not actual:
            errors.append(f'{file}: missing target: {link}'); continue
        if url.fragment and actual in pages and unquote(url.fragment) not in pages[actual].ids:
            errors.append(f'{file}: missing fragment: {link}')
        count += 1
if errors: raise SystemExit('\n'.join(errors))
print(f'Checked {count} local links and fragments across {len(pages)} HTML pages.')
