# test_rf_fox_cli.py

import unittest
from unittest.mock import patch, MagicMock
import base64
import os
import threading
import time
from rf_fox_cli import (
    encrypt_message,
    decrypt_message,
    fldigi_listener,
    AES_KEY,
    messages,
    messages_lock,
)

class TestEncryptionFunctions(unittest.TestCase):
    def test_encrypt_decrypt(self):
        message = "Hello, World!"
        encrypted = encrypt_message(AES_KEY, message)
        decrypted = decrypt_message(encrypted, AES_KEY)
        self.assertEqual(decrypted, message)

    def test_decrypt_invalid_data(self):
        invalid_encrypted = "invalid_data"
        decrypted = decrypt_message(invalid_encrypted, AES_KEY)
        self.assertIsNone(decrypted)

    def test_encrypt_decrypt_with_different_keys(self):
        message = "Test Message"
        encrypted = encrypt_message(AES_KEY, message)
        wrong_key = os.urandom(16)
        decrypted = decrypt_message(encrypted, wrong_key)
        self.assertIsNone(decrypted)

class TestFldigiListener(unittest.TestCase):
    def setUp(self):
        # Reset messages before each test
        with messages_lock:
            messages["received"] = []
            messages["transmitted"] = []

    @patch("rf_fox_cli.fldigi_client")
    def test_listener_with_encrypted_message(self, mock_fldigi_client):
        # Simulate encrypted received data
        original_message = "Secret Message"
        encrypted_message = encrypt_message(AES_KEY, original_message)
        mock_fldigi_client.text.get_rx_data.return_value = encrypted_message

        # Run listener iteration
        with patch("time.sleep", return_value=None):
            listener_thread = threading.Thread(target=fldigi_listener, daemon=True)
            listener_thread.start()
            time.sleep(0.1)  # Give the thread time to run
            listener_thread.join(0.1)

        with messages_lock:
            self.assertEqual(len(messages["received"]), 1)
            received_msg = messages["received"][0]
            self.assertEqual(received_msg["decrypted"], original_message)

    @patch("rf_fox_cli.fldigi_client")
    def test_listener_with_plaintext_message(self, mock_fldigi_client):
        # Simulate plaintext received data
        plaintext_message = "Hello, this is a test."
        mock_fldigi_client.text.get_rx_data.return_value = plaintext_message

        # Run listener iteration
        with patch("time.sleep", return_value=None):
            listener_thread = threading.Thread(target=fldigi_listener, daemon=True)
            listener_thread.start()
            time.sleep(0.1)
            listener_thread.join(0.1)

        with messages_lock:
            self.assertEqual(len(messages["received"]), 1)
            received_msg = messages["received"][0]
            self.assertIsNone(received_msg["decrypted"])
            self.assertEqual(received_msg["message"], plaintext_message.strip())

    @patch("rf_fox_cli.fldigi_client")
    def test_listener_exception_handling(self, mock_fldigi_client):
        # Simulate an exception in fldigi_client
        mock_fldigi_client.text.get_rx_data.side_effect = Exception("Test Exception")

        # Run listener iteration
        with patch("time.sleep", side_effect=KeyboardInterrupt):
            try:
                fldigi_listener()
            except KeyboardInterrupt:
                pass  # Expected due to patched time.sleep

        # Ensure no messages were added
        with messages_lock:
            self.assertEqual(len(messages["received"]), 0)

class TestMessageHandling(unittest.TestCase):
    def setUp(self):
        # Reset messages before each test
        with messages_lock:
            messages["received"] = []
            messages["transmitted"] = []

    @patch("rf_fox_cli.fldigi_client")
    def test_sending_encrypted_message(self, mock_fldigi_client):
        # Mock fldigi_client methods
        mock_fldigi_client.text.clear_tx.return_value = None
        mock_fldigi_client.text.add_tx.return_value = None
        mock_fldigi_client.main.tx.return_value = None

        input_message = "Encrypted Test Message"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Simulate sending an encrypted message
        encrypted = encrypt_message(AES_KEY, input_message)
        with messages_lock:
            messages["transmitted"].append({
                "encrypted": encrypted,
                "decrypted": input_message,
                "timestamp": timestamp,
            })

        # Verify that the message was stored correctly
        with messages_lock:
            self.assertEqual(len(messages["transmitted"]), 1)
            sent_msg = messages["transmitted"][0]
            self.assertEqual(sent_msg["decrypted"], input_message)
            self.assertEqual(sent_msg["encrypted"], encrypted)

    @patch("rf_fox_cli.fldigi_client")
    def test_sending_plaintext_message(self, mock_fldigi_client):
        # Mock fldigi_client methods
        mock_fldigi_client.text.clear_tx.return_value = None
        mock_fldigi_client.text.add_tx.return_value = None
        mock_fldigi_client.main.tx.return_value = None

        input_message = "Plaintext Test Message"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Simulate sending a plaintext message
        with messages_lock:
            messages["transmitted"].append({
                "message": input_message,
                "timestamp": timestamp,
            })

        # Verify that the message was stored correctly
        with messages_lock:
            self.assertEqual(len(messages["transmitted"]), 1)
            sent_msg = messages["transmitted"][0]
            self.assertEqual(sent_msg["message"], input_message)

if __name__ == "__main__":
    unittest.main()
