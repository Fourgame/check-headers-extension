# Gemini-powered Flask API & WebSocket Server

This project provides a backend service for analyzing HTTP Security Headers using Google's Gemini language model via REST and WebSocket APIs.

## Installation

1. **Clone the repository**:
```bash
git clone https://github.com/your-repo/gemini-header-checker.git
cd gemini-header-checker
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

> Make sure you are using Python 3.8 or above.

3. **Run the server**:
```bash
python app.py
```

> The server will start on `http://localhost:5000` by default.

## Gemini API Key

You must have a valid API key from Google Generative AI. Get it at: [https://makersuite.google.com/app/apikey](https://makersuite.google.com/app/apikey)

## Features

- Analyze HTTP Security Headers using Gemini LLM
- WebSocket support for real-time interaction
- AI explanations for header misconfiguration
- CORS and rate-limit protection included

---

Created for research and educational purposes.