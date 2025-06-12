# CHECK-HEADER-OWASP: HTTP Security Analysis Project

This is a complete research and development project focused on evaluating, analyzing, and improving the use of HTTP Security Headers across one million real-world websites. It includes a large-scale dataset, a Chrome extension for real-time inspection, and an AI-powered backend using Gemini for intelligent feedback.

## Data Collection Date

All security header data was collected on **May 16, 2025**, using a custom Python crawler based on the Majestic Million dataset. The DOM analysis and AI-assisted evaluation were performed using the Check Header OWASP Chrome Extension during the same date.

---

## Project Structure

```
CHECK-HEADER-OWASP/
│
├── 1_Millon_Website_Analyse/        # Dataset and analysis results
│   ├── analysis_missconfig.ipynb
│   ├── combined_all_part3.csv
│   └── results_summary.txt
│
├── Backend/                         # Gemini API Flask server
│   ├── backend_api.py
│   ├── requirements.txt
│   └── README_Gemini_API_Backend.md
│
├── Check-Header-extention/         # Chrome Extension source
│   ├── background.js
│   ├── content.js
│   ├── domAnalyzer.js
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── README.md
│
├── My-Peper/
│   └── A_Measurement_Study_*.docx   # Final academic paper
```

---

## How to Run the Chrome Extension

1. Open Google Chrome
2. Navigate to `chrome://extensions/`
3. Enable **Developer Mode** (top-right toggle)
4. Click **Load Unpacked**
5. Select the `Check-Header-extention/` folder
6. Open any website → click the extension icon to inspect headers & DOM

> Make sure you allow permission popups when loading headers.

---

## How to Run the Gemini Python Backend

### Step 1: Install Requirements

```bash
cd Backend
pip install -r requirements.txt
```

### Step 2: Get Your Gemini API Key

- Go to: https://makersuite.google.com/app/apikey
- Generate an API key (free account available)

### Step 3: Start the Flask Server

```bash
python backend_api.py
```

> The API will start at `http://localhost:5000`

### API Endpoints

- `POST /analyze` – analyze headers via Gemini
- `WebSocket /question` – real-time Q&A powered by Gemini

---

## Notes

- The extension interacts with the Gemini backend to provide natural-language explanations for HTTP headers.
- DOM issues (inline script, iframe, unsafe meta) are detected and can be patched directly from the UI.
- All components work offline except AI analysis, which requires internet and an API key.

---

## Supported HTTP Security Headers

Includes 17 OWASP-recommended headers such as:
- Content-Security-Policy
- X-Frame-Options
- Strict-Transport-Security
- Referrer-Policy
- Permissions-Policy
- and more...

---

Created by [Your Name] for security research and academic purposes.