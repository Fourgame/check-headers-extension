# Check Header OWASP – Chrome Extension

This Chrome extension helps developers, security researchers, and end-users **analyze, detect, and apply security headers and DOM protections** in real time. It supports **all 17 HTTP Security Headers** recommended by OWASP and includes DOM-level inspection and AI-powered explanations.

## Features

- ✅ Real-time analysis of HTTP response headers
- ✅ Detection of missing, misconfigured, or deprecated headers
- ✅ DOM inspection: inline scripts, iframes, eval, and meta-policy issues
- ✅ Inline DOM security patching (e.g., adding `sandbox`, rewriting insecure `<script>`)
- ✅ Apply mode: inject secure headers dynamically
- ✅ AI explanation using Gemini (via Flask backend)

## Project Structure

| File              | Description                                                  |
|-------------------|--------------------------------------------------------------|
| `manifest.json`   | Chrome Extension manifest (v3)                               |
| `popup.html`      | Popup interface to display header & DOM results              |
| `popup.js`        | Logic to show analysis results and send apply commands       |
| `background.js`   | Intercepts headers and applies modified values               |
| `content.js`      | Injected script to inspect and fix DOM security issues       |
| `domAnalyzer.js`  | Helper module for DOM analysis logic                         |

## Installation (Developer Mode)

1. Clone or download the repo.
2. Open Chrome and go to: `chrome://extensions/`
3. Enable **Developer Mode**
4. Click **Load unpacked** and select the folder containing all files

## Gemini AI Backend (Optional)

To enable Gemini AI analysis:

```bash
git clone <repo>
cd <repo>
pip install -r requirements.txt
python gemini_server.py
```

Then add your Gemini API key in the popup interface.

## 🛠 Apply Headers

- The extension supports full injection of any of the 17 OWASP headers.
- You can edit header values directly and **apply** them to active pages.

## Supported Headers (OWASP)

- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Content-Security-Policy`
- `X-Permitted-Cross-Domain-Policies`
- `Referrer-Policy`
- `Clear-Site-Data`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Resource-Policy`
- `Cache-Control`
- `Permissions-Policy`
- `Expect-CT`
- `Public-Key-Pins` (deprecated)
- `X-XSS-Protection` (deprecated)
- `Pragma`
- `Feature-Policy` (legacy)

## Screenshot

> _(You can insert screenshots or diagrams here to help users understand the UI.)_

## Reference

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Docs – HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [Gemini Language Model](https://ai.google.dev/gemini)