# Legacy Python microservice with insecure crypto patterns

import hashlib
import random

# VULN: Hardcoded authentication token
AUTH_TOKEN = "DUMMY_TOKEN_ABCDEF1234567890_EXAMP"

def hash_password(password):
    # VULN: MD5 digest
    return hashlib.md5(password.encode()).hexdigest()

def generate_session_token():
    # VULN: Insecure random for token
    token = ''.join(chr(random.randint(65, 90)) for _ in range(32))
    return token

def get_cipher():
    # VULN: RC4 cipher
    cipher_name = "RC4"
    return cipher_name
