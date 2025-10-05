from flask import Flask, render_template, jsonify, Response, request, redirect, url_for, session
import requests, base64, hashlib, json
from cryptography.fernet import Fernet
from flask_cors import CORS

# Flask app setup
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

app.secret_key = "super-secret-key-change-me"  # required for sessions

# Derive Fernet key from string password
def get_key_from_password(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Decrypt JSON file and load into Python dict
def decrypt_json(encrypted_file, password="theSecret"):
    key = get_key_from_password(password)
    fernet = Fernet(key)
    with open(encrypted_file, "rb") as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    return json.loads(decrypted.decode("utf-8"))
 
# Load encrypted data
all_videos_data = decrypt_json("data.enc", password="theSecret101")

# Password for login
APP_PASSWORD = "nopassword!123"   # <-- set your password here

@app.route("/", methods=["GET", "POST"])
def home():
    if "authenticated" in session and session["authenticated"]:
        return render_template("index.html")

    if request.method == "POST":
        entered_password = request.form.get("password")
        if entered_password == APP_PASSWORD:
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Invalid password!")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/json_data")
def json_data():
    if "authenticated" not in session or not session["authenticated"]:
        return {"error": "Unauthorized"}, 401
    return jsonify(all_videos_data)

@app.route("/video")
def stream_video():
    if "authenticated" not in session or not session["authenticated"]:
        return {"error": "Unauthorized"}, 401

    video_url = request.args.get("url")
    if not video_url:
        return "No video URL provided", 400

    # Forward browser's Range header to the origin
    range_header = request.headers.get("Range", None)
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "video",
        "sec-fetch-mode": "no-cors",
        "sec-fetch-site": "same-site",
        "referer": "https://forcedcinema.net/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    }

    if range_header:
        headers["Range"] = range_header

    # Make the request to the original video server
    r = requests.get(video_url, headers=headers, stream=True)

    # Build response headers
    response_headers = {
        "Content-Type": r.headers.get("Content-Type", "video/mp4"),
        "Content-Length": r.headers.get("Content-Length", None),
        "Accept-Ranges": "bytes"
    }

    # If partial content, include Content-Range
    if r.status_code == 206 and "Content-Range" in r.headers:
        response_headers["Content-Range"] = r.headers["Content-Range"]

    return Response(
        r.iter_content(chunk_size=1024),
        status=r.status_code,
        headers=response_headers
    )

if __name__ == "__main__":
    app.run(debug=True)
    
