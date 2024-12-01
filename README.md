# Disclaimer ⚠️

**IMPORTANT: READ THIS BEFORE USING THIS PROJECT**

This project is intended **strictly for educational purposes** to demonstrate concepts in radio frequency (RF) transmission and encryption. **The use of encrypted RF transmissions is illegal in many jurisdictions** without proper authorization, as it can interfere with public safety communications and other critical systems. It is your responsibility to comply with all applicable laws and regulations.

By using this code, you agree that the authors and contributors to this project are **not responsible** for any actions you take with it. Any misuse, including illegal or unauthorized RF encryption, is solely at your own risk.

Please, don’t be that person who causes havoc with RF signals. The world has enough problems already.

---

### Zombie Apocalypse Exception 🧟‍♂️  
If society collapses, and you’re using this to coordinate with your survivor squad against the undead, we won’t hold it against you. Until then, play by the rules!

# RF Fox: Secure Message Broadcasting with Fldigi

RF Fox is a Flask-based application that enables secure message broadcasting using the Fldigi software modem. Messages can be encrypted using AES encryption or sent unencrypted, depending on user preference. It also includes a web interface for managing messages and operating modes.

## Features

- **Secure Broadcasting**: Messages can be sent encrypted with AES-128 encryption.
- **Unencrypted Option**: Allows sending plain-text messages when encryption is not required.
- **Web Interface**: Includes an intuitive web UI for:
  - Sending messages
  - Viewing transmitted and received messages
  - Switching between operating modes supported by Fldigi
- **Real-Time Communication**: Uses the Fldigi XML-RPC interface for communication with the modem.

---

## Requirements

- Python 3.6+
- Fldigi (configured with XML-RPC enabled)
- Required Python Libraries:
  - `pyfldigi`
  - `flask`
  - `pycryptodome`

License

This project is licensed under the MIT License. See the LICENSE file for details.
Contributing

Contributions are welcome! Please submit a pull request or open an issue to suggest improvements or report bugs.
