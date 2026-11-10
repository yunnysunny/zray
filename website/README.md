# zray website

A single static page: one HTML file, one stylesheet, one script, one favicon.
No build step, no dependencies, no external fonts or CDNs — it works offline and
behind a firewall.

```
website/
  index.html         the whole page (bilingual: zh / en)
  assets/style.css   design: warm paper, hairline rules, serif headings
  assets/app.js      language switch + copy buttons
  favicon.svg
```

## Preview locally

```sh
cd website
python3 -m http.server 8000
# open http://localhost:8000/
```

Opening `index.html` directly also works; the page makes no network requests.

## Language

The page ships both languages in the same HTML (`<span lang="zh">` /
`<span lang="en">` pairs) and shows one of them via `data-lang` on `<html>`.
The first visit picks the browser language, then the choice is remembered in
`localStorage`. Add `?lang=en` or `?lang=zh` to the URL to force one, which is
handy when sharing a link.

## Deploying to GitHub Pages

The site is self-contained, so any static host works. For GitHub Pages, either

- enable Pages with the branch/folder source `master` → `/website`, or
- add a workflow that uploads `website/` with `actions/upload-pages-artifact`
  and deploys it with `actions/deploy-pages`.

Everything in `index.html` that points at docs or release notes uses absolute
`github.com/yunnysunny/zray` URLs, so the published copy needs no path fixes.

## Editing

Numbers on the page (binary size, RSS, throughput) are copied from the measured
tables in [../README.md](../README.md); the binary size tracks the mipsel
artifact of the current release. When those measurements change, update both.
