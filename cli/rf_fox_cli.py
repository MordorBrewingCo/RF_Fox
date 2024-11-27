import base64
import hashlib
import logging
import os
import threading
import time
import curses
import pyfldigi
from Crypto.Cipher import AES

# Constants
AES_KEY_SIZE = 16
AES_KEY = hashlib.sha256(b"d2a7a6abeb88d67684c8abb8fde01316").digest()[:AES_KEY_SIZE]

# Initialize pyfldigi
fldigi_client = pyfldigi.Client()

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Shared messages dictionary (with thread-safety)
messages_lock = threading.Lock()
messages = {"received": [], "transmitted": []}

# Encryption enabled flag
encryption_enabled = True

# AES decryption function
def decrypt_message(encrypted_message, key):
    try:
        encrypted_data = base64.b64decode(encrypted_message)
        if len(encrypted_data) < AES.block_size:
            raise ValueError("Invalid encrypted data length.")
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None

# AES encryption function
def encrypt_message(key, message):
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted = iv + cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

# Listener thread function
def fldigi_listener():
    logger.info("Starting fldigi listener thread...")
    previous_data = ""
    while True:
        try:
            # Get new data from fldigi
            current_data = fldigi_client.text.get_rx_data()
            new_data = current_data[len(previous_data):]
            previous_data = current_data

            if new_data.strip():
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                with messages_lock:
                    decrypted_text = decrypt_message(new_data.strip(), AES_KEY)
                    messages["received"].append({
                        "message": new_data.strip(),
                        "decrypted": decrypted_text,
                        "timestamp": timestamp,
                    })
                if decrypted_text:
                    logger.info(f"Decrypted message: {decrypted_text}")
                else:
                    logger.info(f"Received plaintext message: {new_data.strip()}")

            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Error in fldigi listener: {e}")
            time.sleep(5)

def main(stdscr):
    global encryption_enabled
    # Clear screen
    stdscr.clear()
    curses.echo()
    curses.curs_set(1)

    input_win = curses.newwin(3, curses.COLS, curses.LINES - 3, 0)
    input_win.border()
    input_win.addstr(1, 1, "Enter message (/help for commands): ")

    messages_win = curses.newwin(curses.LINES - 3, curses.COLS, 0, 0)
    messages_win.scrollok(True)

    while True:
        # Display messages
        messages_win.clear()
        with messages_lock:
            all_messages = messages["received"] + messages["transmitted"]
            all_messages.sort(key=lambda x: x["timestamp"])

            for msg in all_messages[-(curses.LINES - 4):]:
                timestamp = msg["timestamp"]
                if "decrypted" in msg and msg["decrypted"]:
                    display_msg = f"{timestamp} - {msg['decrypted']}"
                else:
                    display_msg = f"{timestamp} - {msg.get('message', '')}"
                messages_win.addstr(display_msg + "\n")

        messages_win.refresh()
        input_win.refresh()

        # Get user input
        input_str = input_win.getstr(1, 36).decode('utf-8').strip()
        if input_str.lower() == "/quit":
            break
        elif input_str.lower() == "/encrypt on":
            encryption_enabled = True
            input_win.addstr(1, 1, "Encryption enabled.                        ")
        elif input_str.lower() == "/encrypt off":
            encryption_enabled = False
            input_win.addstr(1, 1, "Encryption disabled.                       ")
        elif input_str.lower() == "/help":
            input_win.addstr(1, 1, "Commands: /encrypt on, /encrypt off, /quit ")
        elif input_str.startswith("/"):
            input_win.addstr(1, 1, "Unknown command.                           ")
        else:
            # Send message
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            if encryption_enabled:
                encrypted_message = encrypt_message(AES_KEY, input_str)
                fldigi_client.text.clear_tx()
                fldigi_client.text.add_tx(encrypted_message)
                fldigi_client.main.tx()
                with messages_lock:
                    messages["transmitted"].append({
                        "encrypted": encrypted_message,
                        "decrypted": input_str,
                        "timestamp": timestamp,
                    })
            else:
                fldigi_client.text.clear_tx()
                fldigi_client.text.add_tx(input_str)
                fldigi_client.main.tx()
                with messages_lock:
                    messages["transmitted"].append({
                        "message": input_str,
                        "timestamp": timestamp,
                    })

        # Clear input line
        input_win.clear()
        input_win.border()
        input_win.addstr(1, 1, "Enter message (/help for commands): ")

if __name__ == "__main__":
    listener_thread = threading.Thread(target=fldigi_listener, daemon=True)
    listener_thread.start()
    curses.wrapper(main)
