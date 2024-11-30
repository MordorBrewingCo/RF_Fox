import base64
import logging
import os
import threading
import time

import pyfldigi
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from flask import Flask, render_template_string

# Constants
KEY_DIR = os.path.expanduser("~/.rf_fox")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")

# Flask app setup
app = Flask(__name__)

# Initialize pyfldigi
fldigi_client = pyfldigi.Client()

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Shared messages dictionary (with thread-safety)
messages_lock = threading.Lock()
messages = {"received": [], "transmitted": []}


def generate_rsa_keys():
    """Generates RSA key pair and saves them to ~/.rf_fox directory."""
    os.makedirs(KEY_DIR, exist_ok=True)
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(PRIVATE_KEY_PATH, "wb") as private_file:
        private_file.write(private_key)

    with open(PUBLIC_KEY_PATH, "wb") as public_file:
        public_file.write(public_key)

    logger.info("RSA key pair generated and saved to ~/.rf_fox")


def load_rsa_keys():
    """Loads RSA private and public keys, generating them if not present."""
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        generate_rsa_keys()

    with open(PRIVATE_KEY_PATH, "rb") as private_file:
        private_key = RSA.import_key(private_file.read())

    with open(PUBLIC_KEY_PATH, "rb") as public_file:
        public_key = RSA.import_key(public_file.read())

    return private_key, public_key


# Load RSA keys
private_key, public_key = load_rsa_keys()
private_cipher = PKCS1_OAEP.new(private_key)
public_cipher = PKCS1_OAEP.new(public_key)


def decrypt_message(encrypted_message):
    try:
        encrypted_data = base64.b64decode(encrypted_message)
        plaintext = private_cipher.decrypt(encrypted_data)
        return plaintext.decode("utf-8")
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None


def encrypt_message(message):
    try:
        ciphertext = public_cipher.encrypt(message.encode("utf-8"))
        return base64.b64encode(ciphertext).decode("utf-8")
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return None


def fldigi_listener():
    logger.info("Starting fldigi listener thread...")
    while True:
        try:
            received_text = fldigi_client.text.get_rx_data()
            if received_text:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

                with messages_lock:
                    decrypted_text = decrypt_message(received_text)
                    messages["received"].append({
                        "message": received_text,
                        "decrypted": decrypted_text,
                        "timestamp": timestamp,
                    })
                if decrypted_text:
                    logger.info(f"Decrypted message: {decrypted_text}")
                else:
                    logger.info(f"Received plaintext message: {received_text}")

            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Error in fldigi listener: {e}")
            time.sleep(5)


@app.route("/", methods=["GET", "POST"])
def index():
    try:
        return render_template_string(
            '''
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>RF Fox</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 20px;
                        padding: 0;
                        text-align: left;
                    }
                    .top-right-nav {
                        position: absolute;
                        top: 10px;
                        right: 10px;
                        display: flex;
                        gap: 10px;
                    }
                    .top-right-nav a {
                        text-decoration: none;
                        color: #007BFF;
                        font-weight: bold;
                        padding: 5px 10px;
                        border-radius: 5px;
                        transition: background-color 0.3s ease;
                    }
                    .top-right-nav a:hover {
                        background-color: #f0f0f0;
                    }
                </style>
            </head>
            <body>
                <div class="top-right-nav">
                    <a href="/settings">Settings</a>
                    <a href="/public_key">My Public Key</a>
                </div>
                <img src="static/logo.png" alt="RF Fox Logo">
                <h1>Broadcast a Message</h1>
                <form method="POST" action="/broadcast">
                    <label for="message">Message:</label>
                    <textarea id="message" name="message" required style="resize: both; width: 100%; height: 100px;"></textarea>
                    <br><br>
                    <label for="encryption">Send as:</label>
                    <select id="encryption" name="encryption">
                        <option value="encrypted" selected>Encrypted</option>
                        <option value="unencrypted">Unencrypted</option>
                    </select>
                    <br><br>
                    <input type="submit" value="Broadcast">
                </form>
                <h2>Received Messages</h2>
                <ul>
                {% for msg in messages["received"] %}
                    <li>{{ msg.timestamp }} - {{ msg.message }}</li>
                {% endfor %}
                </ul>
                <h2>Transmitted Messages</h2>
                <ul>
                {% for msg in messages["transmitted"] %}
                    <li>
                        <strong>Timestamp:</strong> {{ msg.timestamp }}<br>
                        {% if msg.encrypted %}
                            <strong>Encrypted:</strong> {{ msg.encrypted }}<br>
                            <strong>Decrypted:</strong> {{ msg.decrypted }}
                        {% else %}
                            <strong>Message:</strong> {{ msg.decrypted }}
                        {% endif %}
                    </li>
                {% endfor %}
                </ul>
            </body>
            </html>
            ''',
            messages=messages,
        )
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return "<h1>Error loading index page</h1>"


@app.route("/public_key", methods=["GET"])
def public_key_page():
    try:
        with open(PUBLIC_KEY_PATH, "r") as public_file:
            public_key_content = public_file.read()

        return render_template_string(
            '''
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>My Public Key</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 20px;
                        padding: 0;
                        text-align: left;
                    }
                    .key-container {
                        background-color: #f9f9f9;
                        padding: 20px;
                        border: 1px solid #ddd;
                        border-radius: 5px;
                        word-wrap: break-word;
                        font-family: monospace;
                    }
                    .back-link {
                        display: inline-block;
                        margin-top: 20px;
                        text-decoration: none;
                        color: #007BFF;
                        font-weight: bold;
                        padding: 5px 10px;
                        border-radius: 5px;
                        transition: background-color 0.3s ease;
                    }
                    .back-link:hover {
                        background-color: #f0f0f0;
                    }
                </style>
            </head>
            <body>
                <h1>My Public Key</h1>
                <div class="key-container">
                    <pre>{{ public_key }}</pre>
                </div>
                <a href="/" class="back-link">Back to Home</a>
            </body>
            </html>
            ''',
            public_key=public_key_content,
        )
    except Exception as e:
        logger.error(f"Error in public key page: {e}")
        return "<h1>Error loading public key page</h1><a href='/'>Back to Home</a>"


if __name__ == "__main__":
    listener_thread = threading.Thread(target=fldigi_listener, daemon=True)
    listener_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
