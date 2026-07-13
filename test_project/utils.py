import hashlib
import random
import pickle
import os

def hash_password(password):
    # Weak hashing algorithm for passwords
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # Insecure randomness for a security token
    return str(random.random())

def load_user_data(raw_bytes):
    # Insecure deserialization
    return pickle.loads(raw_bytes)

def read_user_file(filename):
    # Path traversal - no sanitization of filename
    path = os.path.join("/var/app/uploads/", filename)
    with open(path) as f:
        return f.read()
