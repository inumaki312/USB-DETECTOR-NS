import gnupg
import os

def setup_gpg():
    """Initialize GPG with default settings"""
    try:
        gpg = gnupg.GPG()
        return gpg
    except Exception as e:
        print(f"Warning: GPG setup failed: {e}")
        return None

def encrypt_file(filename):
    """Encrypt the given file using GPG"""
    try:
        gpg = setup_gpg()
        if gpg:
            with open(filename, 'rb') as f:
                status = gpg.encrypt_file(
                    f,
                    recipients=None,
                    symmetric='AES256',
                    passphrase='usbdetector',
                    output=f'{filename}.gpg'
                )
            if status.ok:
                os.remove(filename)  # Remove original file after encryption
                return True
    except Exception as e:
        print(f"Warning: Encryption failed: {e}")
    return False 