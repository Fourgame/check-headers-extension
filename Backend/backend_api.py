from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import google.generativeai as genai
import logging
import time

# ---------- CONFIG ----------
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
logging.basicConfig(level=logging.INFO)

# cooldown tracking per client (WebSocket)
last_call = {}

# ---------- ROUTES ----------
@app.route('/')
def index():
    return "LLM Gemini-only API is up."

@app.route('/analyze', methods=['POST'])
def analyze_headers():
    data = request.json
    api_key = data.get("apiKey")
    headers = data.get("headers")

    if not api_key or not headers or not isinstance(headers, dict) or not headers:
        return jsonify({"error": "Missing or invalid apiKey/headers"}), 400

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")

        prompt = (
            "Analyze the following HTTP Security Headers and provide a brief security summary:\n\n"
            + "\n".join([f"{k}: {v}" for k, v in headers.items()])
        )

        logging.info(f"[Gemini Prompt]:\n{prompt}")
        response = model.generate_content(prompt)
        return jsonify({"result": response.text})

    except Exception as e:
        logging.error(f"[Gemini Error]: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ---------- WEBSOCKET ----------
@socketio.on('question')
def handle_question(data):
    question = data.get("question", "")
    api_key = data.get("apiKey")
    client_id = request.sid

    if not api_key or not question:
        emit("answer", "[ERROR] Missing question or Gemini API Key")
        return

    now = time.time()
    if client_id in last_call and now - last_call[client_id] < 2:  # 2 sec cooldown
        emit("answer", "[ERROR] Too frequent. Please wait.")
        return
    last_call[client_id] = now

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(question)
        emit("answer", response.text)
    except Exception as e:
        logging.error(f"[WebSocket Gemini Error]: {str(e)}")
        emit("answer", f"[Gemini Error] {str(e)}")

# ---------- MAIN ----------
if __name__ == '__main__':
    print("🔌 Starting Gemini-only LLM backend...")
    socketio.run(app, host='0.0.0.0', port=5000)
