import streamlit as st
import os
import json
import time
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Constants
DATA_FILE = "data.json"
LOCKOUT_DURATION = 300  # 5 minutes in seconds
MAX_ATTEMPTS = 3

# Load data
def load_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump({}, f)
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

data_store = load_data()

# Utilities
def generate_key(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_data(data, passkey):
    salt = os.urandom(16)
    key = generate_key(passkey, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted.decode(), base64.b64encode(salt).decode()

def decrypt_data(encrypted, passkey, salt_b64):
    try:
        salt = base64.b64decode(salt_b64)
        key = generate_key(passkey, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted.encode()).decode()
    except:
        return None

def hash_password(password):
    return hashes.SHA256(password.encode()).hexdigest()

# Session state init
for key in ['user', 'attempts', 'lockout_time']:
    if key not in st.session_state:
        st.session_state[key] = None

# UI Functions
def signup():
    st.subheader("Create a New Account")
    username = st.text_input("Username", key="signup_user")
    password = st.text_input("Password", type='password', key="signup_pass")

    if st.button("Sign Up"):
        if username in data_store:
            st.warning("Username already exists.")
        elif username and password:
            data_store[username] = {
                "password": hash_password(password),
                "data": None,
                "salt": None
            }
            save_data(data_store)
            st.success("Account created! Please log in.")

def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = data_store.get(username)
        if user and user['password'] == hash_password(password):
            st.session_state.user = username
            st.session_state.attempts = 0
            st.session_state.lockout_time = None
            st.success(f"Welcome {username}!")
        else:
            st.error("Invalid credentials.")

def main_app():
    user = st.session_state.user
    st.title(f"🔐 Welcome, {user}!")

    if st.button("Logout"):
        st.session_state.user = None
        return

    tab1, tab2 = st.tabs(["🔏 Store Data", "🔓 Retrieve Data"])

    with tab1:
        data_input = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter passkey", type='password', key="store_pass")

        if st.button("Encrypt and Store"):
            if data_input and passkey:
                encrypted, salt = encrypt_data(data_input, passkey)
                data_store[user]["data"] = encrypted
                data_store[user]["salt"] = salt
                save_data(data_store)
                st.success("Data encrypted and saved.")
            else:
                st.warning("Both fields are required.")

    with tab2:
        passkey = st.text_input("Enter your passkey to decrypt", type="password", key="retrieve_pass")

        # Lockout check
        if st.session_state.attempts >= MAX_ATTEMPTS:
            if st.session_state.lockout_time and time.time() < st.session_state.lockout_time + LOCKOUT_DURATION:
                remaining = int((st.session_state.lockout_time + LOCKOUT_DURATION) - time.time())
                st.error(f"Locked out! Try again in {remaining} seconds.")
                return
            else:
                st.session_state.attempts = 0
                st.session_state.lockout_time = None

        if st.button("Decrypt"):
            encrypted = data_store[user].get("data")
            salt = data_store[user].get("salt")
            if not encrypted or not salt:
                st.warning("No data to decrypt.")
            else:
                decrypted = decrypt_data(encrypted, passkey, salt)
                if decrypted:
                    st.success("Decryption successful!")
                    st.code(decrypted)
                    st.session_state.attempts = 0
                else:
                    st.session_state.attempts += 1
                    if st.session_state.attempts >= MAX_ATTEMPTS:
                        st.session_state.lockout_time = time.time()
                        st.error("Too many attempts. Locked out!")
                    else:
                        st.error(f"Wrong passkey. {MAX_ATTEMPTS - st.session_state.attempts} attempts left.")

# App Routing
st.set_page_config("Secure Vault", layout="centered", page_icon="🔐")

if not st.session_state.user:
    st.title("🛡 Secure Data Encryption System")
    login()
    st.markdown("---")
    signup()
else:
    main_app()
