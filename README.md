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
