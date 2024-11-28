import base64
import logging
import os
import threading
import time

import pyfldigi
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from flask import Flask, request, render_template_string

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


# RSA decryption function
def decrypt_message(encrypted_message):
    try:
        encrypted_data = base64.b64decode(encrypted_message)
        plaintext = private_cipher.decrypt(encrypted_data)
        return plaintext.decode("utf-8")
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None


# RSA encryption function
def encrypt_message(message):
    try:
        ciphertext = public_cipher.encrypt(message.encode("utf-8"))
        return base64.b64encode(ciphertext).decode("utf-8")
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return None


# Listener thread function
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
            </head>
            <body>
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
                <a href="/settings">Go to Settings</a>
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


@app.route("/broadcast", methods=["POST"])
def broadcast():
    try:
        message = request.form.get("message")
        encryption_choice = request.form.get("encryption")

        if not message or len(message) > 1024:
            return "<h1>Error: Message cannot be empty or too long!</h1><a href='/'>Try Again</a>"

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if encryption_choice == "unencrypted":
            fldigi_client.text.clear_tx()
            fldigi_client.text.add_tx(message)
            fldigi_client.main.tx()
        else:
            encrypted_message = encrypt_message(message)
            fldigi_client.text.clear_tx()
            fldigi_client.text.add_tx(encrypted_message)
            fldigi_client.main.tx()

        with messages_lock:
            messages["transmitted"].append({
                "encrypted": encrypt_message(message) if encryption_choice == "encrypted" else None,
                "decrypted": message,
                "timestamp": timestamp,
            })

        return "<h1>Message Broadcast Successfully!</h1><a href='/'>Back</a>"
    except Exception as e:
        logger.error(f"Error during broadcast: {e}")
        return f"<h1>Error: {str(e)}</h1><a href='/'>Try Again</a>"

@app.route("/settings", methods=["GET", "POST"])
def settings():
    try:
        current_mode = fldigi_client.modem.name
        modes = fldigi_client.modem.names

        if request.method == "POST":
            new_mode = request.form.get("mode")
            if new_mode and new_mode in modes:
                fldigi_client.modem.name = new_mode
                logger.info(f"Mode changed to {new_mode}")

        return render_template_string(
            '''
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>RF Fox - Settings</title>
            </head>
            <body>
                <h1>Settings</h1>
                <h2>Operating Mode</h2>
                <form method="POST" action="/settings">
                    <label for="mode">Select Mode:</label>
                    <select id="mode" name="mode">
                        {% for mode in modes %}
                        <option value="{{ mode }}" {% if mode == current_mode %}selected{% endif %}>{{ mode }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit">Change Mode</button>
                </form>
                <h2>Current Mode: {{ current_mode }}</h2>
                <a href="/">Back to Home</a>
            </body>
            </html>
            ''',
            current_mode=current_mode,
            modes=modes,
        )
    except Exception as e:
        logger.error(f"Error in settings route: {e}")
        return "<h1>Error loading settings page</h1>"

if __name__ == "__main__":
    listener_thread = threading.Thread(target=fldigi_listener, daemon=True)
    listener_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
