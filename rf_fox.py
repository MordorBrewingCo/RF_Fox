import base64
import logging
import os
import threading
import time

import pyfldigi
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from flask import Flask, render_template_string, request

# Constants
KEY_DIR = os.path.expanduser("~/.rf_fox")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")
PUBLIC_KEYS_DIR = os.path.join(KEY_DIR, "public_keys")

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
    """Listens for incoming messages from fldigi."""
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
    """Homepage for broadcasting messages."""
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
                <img src="static/logo.png" alt="RF Fox Logo" style="max-width: 200px; margin-bottom: 20px;">
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


@app.route("/broadcast", methods=["POST"])
def broadcast():
    """Handles broadcasting messages."""
    try:
        message = request.form.get("message", "")
        encryption_choice = request.form.get("encryption", "encrypted")

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


@app.route("/public_key", methods=["GET"])
def public_key_page():
    """Displays the user's public key."""
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
                <script>
                    function copyToClipboard() {
                        const publicKey = document.getElementById("publicKey").innerText;
                        navigator.clipboard.writeText(publicKey).then(() => {
                            alert("Public key copied to clipboard!");
                        }).catch(err => {
                            alert("Failed to copy public key: " + err);
                        });
                    }
                </script>
            </head>
            <body>
                <h1>My Public Key</h1>
                <pre id="publicKey">{{ public_key }}</pre>
                <button onclick="copyToClipboard()">Copy to Clipboard</button>
                <br><br>
                <a href="/">Back to Home</a>
            </body>
            </html>
            ''',
            public_key=public_key_content,
        )
    except Exception as e:
        logger.error(f"Error in public key page: {e}")
        return "<h1>Error loading public key page</h1><a href='/'>Back to Home</a>"


@app.route("/settings", methods=["GET", "POST"])
def settings():
    """Allows users to change operating modes and manage public keys."""
    try:
        os.makedirs(PUBLIC_KEYS_DIR, exist_ok=True)

        current_mode = fldigi_client.modem.name
        modes = fldigi_client.modem.names

        if request.method == "POST":
            # Handle mode change
            if "change_mode" in request.form:
                new_mode = request.form.get("mode")
                if new_mode in modes:
                    fldigi_client.modem.name = new_mode
                    logger.info(f"Mode changed to {new_mode}")

            # Handle public key import
            elif "import_key" in request.form:
                key_alias = request.form.get("key_alias", "").strip()
                public_key_content = request.form.get("public_key", "").strip()
                if key_alias and public_key_content:
                    key_path = os.path.join(PUBLIC_KEYS_DIR, f"{key_alias}.pem")
                    try:
                        RSA.import_key(public_key_content)
                        with open(key_path, "w") as key_file:
                            key_file.write(public_key_content)
                        logger.info(f"Public key '{key_alias}' imported successfully.")
                    except ValueError as e:
                        logger.error(f"Invalid public key format: {e}")

            # Handle public key deletion
            elif "delete_key" in request.form:
                key_alias = request.form.get("key_alias", "").strip()
                key_path = os.path.join(PUBLIC_KEYS_DIR, f"{key_alias}.pem")
                if os.path.exists(key_path):
                    os.remove(key_path)
                    logger.info(f"Public key '{key_alias}' deleted successfully.")
                else:
                    logger.error(f"Public key '{key_alias}' not found.")

        # List stored public keys
        stored_keys = [key.replace(".pem", "") for key in os.listdir(PUBLIC_KEYS_DIR) if key.endswith(".pem")]

        return render_template_string(
            '''
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>RF Fox Settings</title>
            </head>
            <body>
                <h1>Settings</h1>

                <h2>Operating Mode</h2>
                <form method="POST">
                    <input type="hidden" name="change_mode" value="1">
                    <label for="mode">Select Mode:</label>
                    <select id="mode" name="mode">
                        {% for mode in modes %}
                        <option value="{{ mode }}" {% if mode == current_mode %}selected{% endif %}>{{ mode }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit">Change Mode</button>
                </form>
                <h2>Current Mode: {{ current_mode }}</h2>

                <h2>Import Public Key</h2>
                <form method="POST">
                    <input type="hidden" name="import_key" value="1">
                    <label for="key_alias">Key Alias:</label>
                    <input type="text" id="key_alias" name="key_alias" required>
                    <br><br>
                    <label for="public_key">Public Key:</label>
                    <textarea id="public_key" name="public_key" required style="resize: both; width: 100%; height: 100px;"></textarea>
                    <br><br>
                    <button type="submit">Import Key</button>
                </form>

                <h2>Stored Public Keys</h2>
                <ul>
                    {% for key in stored_keys %}
                    <li>
                        {{ key }}
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="delete_key" value="1">
                            <input type="hidden" name="key_alias" value="{{ key }}">
                            <button type="submit" style="color: red;">Delete</button>
                        </form>
                    </li>
                    {% endfor %}
                </ul>

                <a href="/">Back to Home</a>
            </body>
            </html>
            ''',
            current_mode=current_mode,
            modes=modes,
            stored_keys=stored_keys,
        )
    except Exception as e:
        logger.error(f"Error in settings route: {e}")
        return "<h1>Error loading settings page</h1>"


if __name__ == "__main__":
    listener_thread = threading.Thread(target=fldigi_listener, daemon=True)
    listener_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
