# Cristian Garza — Portfolio Site

A Hugo site built from scratch (no third-party theme) — dark slate background,
IBM Plex Sans/Mono type, teal/amber accents. Custom layouts live in `layouts/`,
styling is a single hand-written stylesheet at `static/css/main.css`.

## Run locally

```
hugo server
```

Visit http://localhost:1313

## Before you deploy — things to change

1. **`hugo.toml`**
   - Set `baseURL` to `https://<your-github-username>.github.io/<repo-name>/`
     (or your custom domain if you set one up).
   - Update `github` under `[params]` to your real GitHub URL.

2. **Add your real résumé PDF** at `static/resume.pdf` — the "Download résumé"
   button and nav link both point to `/resume.pdf`.

3. **Write-ups** — two placeholders live in `content/writeups/`. When you have
   a real write-up:
   - Copy one of the placeholder files, remove `placeholder: true`, set a real
     `date`, and write the content in Markdown below the front matter.
   - Delete the placeholder files once you have 2-3 real posts up.

4. **Tools section** — not built yet, since you don't have any public tools
   yet. When you do, the cleanest place to add it is a new section the same
   way `writeups` is built (a `content/tools/` directory + matching layouts),
   or just GitHub-linked cards added directly to the homepage skills section.

## Deploy to GitHub Pages

This repo includes `.github/workflows/hugo.yml`, which builds and deploys on
every push to `main` using GitHub Actions.

1. Push this repo to GitHub.
2. In the repo, go to **Settings → Pages**.
3. Under "Build and deployment," set **Source** to **GitHub Actions**.
4. Push to `main` (or run the workflow manually from the Actions tab).
5. Your site will be live at `https://<username>.github.io/<repo-name>/`.

## Structure

```
content/
  _index.md          → homepage front matter (content is in layouts/index.html)
  writeups/           → blog-style write-up posts
layouts/
  _default/baseof.html  → page shell (head, header, footer)
  index.html            → homepage sections (hero, about, experience, skills, etc.)
  writeups/list.html    → /writeups/ index page
  writeups/single.html  → individual write-up page
  partials/header.html, footer.html
static/
  css/main.css        → all styling
  resume.pdf          → add your résumé here
```
