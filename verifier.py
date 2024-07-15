from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
from sqlalchemy.orm import sessionmaker
from db_setup import Base, engine, DBSession  # Import the setup from db_setup
from models import User, FileRecord  # Ensure User and FileRecord are defined in models

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Set up logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Create a session
db_session = DBSession()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db_session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            session['is_verifier'] = user.is_verifier
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signupv', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        is_verifier = 'is_verifier' in request.form

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Generate a security ID for the new user
        security_id = generate_security_id()

        # Create a new user with the generated security ID and default mobile_number
        new_user = User(
            full_name=full_name,
            email=email,
            username=username,
            password=hashed_password,
            security_id=security_id,
            mobile_number='',
            is_verifier=is_verifier
        )
        
        db_session.add(new_user)
        db_session.commit()

        return redirect(url_for('login'))
    return render_template('signupv.html')

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/profile_setup', methods=['GET', 'POST'])
def profile_setup():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user = db_session.query(User).filter_by(username=session['username']).first()
        user.full_name = request.form['full_name']
        user.email = request.form['email']
        user.mobile_number = request.form['mobile_number']
        user.previous_company = request.form['previous_company']
        user.current_company = request.form['current_company']
        user.security_id = generate_security_id()
        
        db_session.commit()
            
        return redirect(url_for('document_verification'))
    
    return render_template('profile_setup.html')

@app.route('/document_verification')
def document_verification():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    users = db_session.query(User).all()
    return render_template('document_verification.html', users=users)

@app.route('/verify_user_documents/<int:user_id>', methods=['GET', 'POST'])
def verify_user_documents(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = db_session.query(User).filter_by(id=user_id).first()
    if request.method == 'POST':
        file_info_list = []
        for file_record in user.file_records:
            random_number = request.form[f'random_number_{file_record.id}']
            combined_hash = combine_hash_and_random(file_record.file_path, random_number)
            file_info_list.append({'file_path': file_record.file_path, 'generated_hash': combined_hash, 'stored_hash': file_record.file_hash})
        
        return render_template('verify_results.html', file_info_list=file_info_list)
    
    return render_template('verify_user_documents.html', user=user)

def generate_random_number():
    import random
    return random.randint(1, 2**31 - 1)

def generate_security_id():
    import random
    import string
    return ''.join(random.choices(string.digits, k=5))

class OptimizedSHA256:
    def __init__(self):
        self.k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
        self.h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        self.data = b""
        self.bit_length = 0

    def _right_rotate(self, value, shift):
        return (value >> shift) | (value << (32 - shift)) & 0xFFFFFFFF

    def _padding(self):
        orig_len_in_bits = (8 * self.bit_length) & 0xffffffffffffffff
        self.data += b'\x80'
        while len(self.data) % 64 != 56:
            self.data += b'\x00'
        self.data += orig_len_in_bits.to_bytes(8, byteorder='big')

    def _process_block(self, block):
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(block[i * 4:(i + 1) * 4], byteorder='big')
        for i in range(16, 64):
            s0 = self._right_rotate(w[i - 15], 7) ^ self._right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = self._right_rotate(w[i - 2], 17) ^ self._right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self.h

        for i in range(64):
            S1 = self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
            S0 = self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22)
            maj = (a & b) ^ (a & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def update(self, data):
        self.bit_length += len(data)
        self.data += data
        while len(self.data) >= 64:
            self._process_block(self.data[:64])
            self.data = self.data[64:]

    def digest(self):
        self._padding()
        while len(self.data) >= 64:
            self._process_block(self.data[:64])
            self.data = self.data[64:]
        return ''.join([format(h, '08x') for h in self.h])

def compute_file_hash(file_path):
    sha256 = OptimizedSHA256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.digest()

def combine_hash_and_random(file_path, random_number):
    file_hash = compute_file_hash(file_path)
    combined_string = file_hash + str(random_number)
    sha256 = OptimizedSHA256()
    sha256.update(combined_string.encode())
    combined_hash = sha256.digest()
    return combined_hash

if __name__ == '__main__':
    app.run(debug=True)
