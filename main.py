from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from collections import deque
from threading import Lock
import time
import sqlite3
import json
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from argon2.low_level import hash_secret, Type
import base64
import jwt
from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()

# Constants
hostName = "localhost"
serverPort = 8080
DB_FILE = 'totally_not_my_privateKeys.db'

basesalt = os.urandom(16)

# Fetch and decode the secret key
key_hex = os.getenv("NOT_MY_KEY")
if not key_hex:
    raise ValueError("The environment variable 'NOT_MY_KEY' is not set. Please check your .env file.")

try:
    AES_KEY = bytes.fromhex(key_hex)  # Convert hex string to raw bytes
except ValueError:
    raise ValueError("The 'NOT_MY_KEY' value in the .env file is not a valid hexadecimal string.")

if len(AES_KEY) not in [16, 24, 32]:
    raise ValueError("The key must be 128, 192, or 256 bits (16, 24, or 32 bytes).")

# Constants for Rate Limiting
RATE_LIMIT = 10  # Max 10 requests per second
TIME_WINDOW = 1  # 1 second time window
rate_limit_lock = Lock()  # Ensure thread safety

# Data structure to track requests per client
client_request_data = {}


# AES Encryption Helpers
def encrypt_key(private_key: bytes):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(private_key) + encryptor.finalize()
    return iv, encrypted_key

def decrypt_key(iv: bytes, encrypted_key: bytes):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_key) + decryptor.finalize()

# Password Hashing Helpers
def hash_password(password):
    salt = basesalt
    hashed = hash_secret(
        password.encode(),
        salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.ID
    )
    return hashed

def verify_password(plain_password, stored_hash):
    currenthash = hash_password(plain_password)
    currenthash = currenthash.decode("utf-8")
    if currenthash == stored_hash:
        return True
    else:
        return False

# Database Initialization
def init_db():
    if not os.path.exists(DB_FILE):
        print(f"Database file '{DB_FILE}' does not exist. Creating a new one...")
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Create necessary tables
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password_hash TEXT NOT NULL,
                            email TEXT UNIQUE,
                            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP
                          )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            request_ip TEXT NOT NULL,
                            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            user_id INTEGER,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                          )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS keys (
                            kid INTEGER PRIMARY KEY AUTOINCREMENT,
                            key BLOB NOT NULL,
                            iv BLOB NOT NULL,
                            exp INTEGER NOT NULL
                          )''')
        conn.commit()
        print(f"Database '{DB_FILE}' has been successfully created.")
    else:
        print(f"Database file '{DB_FILE}' already exists.")
    return sqlite3.connect(DB_FILE)

def rate_limiter(client_ip):
    """
    Sliding window rate limiter for the POST:/auth endpoint.
    Allows 10 requests per second per client.
    """
    current_time = time.time()

    with rate_limit_lock:  # Ensure atomic access to shared data
        if client_ip not in client_request_data:
            # Initialize a deque to store request timestamps
            client_request_data[client_ip] = deque()

        request_timestamps = client_request_data[client_ip]

        # Remove timestamps outside the current time window
        while request_timestamps and current_time - request_timestamps[0] > TIME_WINDOW:
            request_timestamps.popleft()

        # Check the current number of requests in the window
        if len(request_timestamps) >= RATE_LIMIT:
            # Rate limit exceeded
            return False

        # Add the current timestamp to the deque
        request_timestamps.append(current_time)
        return True

# Key Management
def generate_keys():
    conn = init_db()
    cursor = conn.cursor()
    
    # Generate the first private key
    private_key_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pem_1 = private_key_1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    iv_1, encrypted_key_1 = encrypt_key(pem_1)
    
    # Generate the second private key
    private_key_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pem_2 = private_key_2.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    iv_2, encrypted_key_2 = encrypt_key(pem_2)

    # Expiration times (one expired and one valid)
    expired_time = int(time.time()) - 3600  # 1 hour before current time
    valid_time = int(time.time()) + 3600   # 1 hour from current time

    # Insert the first key with its IV and expiration time
    cursor.execute('INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)', (encrypted_key_1, iv_1, expired_time))

    # Insert the second key with its IV and expiration time
    cursor.execute('INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)', (encrypted_key_2, iv_2, valid_time))

    # Commit changes to the database
    conn.commit()
    conn.close()


# User Management
def register_user(username, email):
    password = str(uuid.uuid4())  # Generate a UUID password
    print(password)
    hashed_password = hash_password(password)  # Securely hash the password
    

    conn = init_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                   (username, hashed_password.decode(), email))
    conn.commit()
    conn.close()

    return {"password": password}

# Logging
def log_auth_request(ip, user_id=None):
    """Log only successful authentication requests"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (ip, user_id))
    conn.commit()
    conn.close()

# JWT Validation Helpers
def generate_jwt(user_id):
    expiration_time = int(time.time()) + 3600  # 1 hour expiration
    payload = {
        "user_id": user_id,
        "exp": expiration_time
    }

    # Private key for signing JWT (you can use your private key stored in DB)
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute('SELECT key , iv FROM keys WHERE exp > ? LIMIT 1', (int(time.time()),))
    key , iv = cursor.fetchone()
    

    if key:
        private_key_pem = decrypt_key(iv , key)  # Decrypt private key
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

        # Sign JWT with the private key
        token = jwt.encode(payload, private_key, algorithm="RS256")
        return token
    else:
        raise Exception("No valid private key found")

# JWKS Logic
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/auth":
            client_ip = self.client_address[0]
            

            if not rate_limiter(client_ip):
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
                return
            
            # Read and parse the request body
            content_length = int(self.headers['Content-Length'])
            post_data = json.loads(self.rfile.read(content_length).decode('utf-8'))

            username = post_data.get('username')
            password = post_data.get('password')
            

            if not username or not password:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing username or password")
                return

            # Check if user exists
            conn = init_db()
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if user:
                user_id, stored_hash = user

                # Verify password
                if verify_password(password, stored_hash):
                    
                    # Generate JWT token
                    token = generate_jwt(user_id)

                    # Log successful login
                    log_auth_request(client_ip, user_id)

                    # Send JWT token in response
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"jwt": token}).encode('utf-8'))
                    return
                else:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Invalid credentials")
                    return
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"User not found")
                return

        if self.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = json.loads(self.rfile.read(content_length).decode('utf-8'))

            username = post_data.get('username')
            email = post_data.get('email')

            try:
                result = register_user(username, email)
                self.send_response(201)
                self.end_headers()
                self.wfile.write(bytes(json.dumps(result), 'utf-8'))
            except sqlite3.IntegrityError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"User already exists or invalid data.")
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            try:
                conn = init_db()
                cursor = conn.cursor()
                cursor.execute("SELECT key, iv FROM keys WHERE exp > ?", (int(time.time()),))
                rows = cursor.fetchall()

                jwks_keys = []
                for encrypted_key, iv in rows:
                    private_key_pem = decrypt_key(iv, encrypted_key)
                    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
                    public_key = private_key.public_key()

                    public_numbers = public_key.public_numbers()
                    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
                    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')

                    jwks_keys.append({
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": str(uuid.uuid4()),
                        "n": n,
                        "e": e
                    })

                jwks = {"keys": jwks_keys}
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(jwks).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                error_message = {"error": "Internal Server Error", "details": str(e)}
                self.wfile.write(json.dumps(error_message).encode('utf-8'))
            finally:
                conn.close()

if __name__ == "__main__":
    generate_keys()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")
