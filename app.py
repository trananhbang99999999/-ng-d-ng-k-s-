from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify
import os
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = 'uploads'
SIGNED_FOLDER = 'signed_files'
KEYS_FOLDER = 'keys'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

# RSA key size options (in bits)
KEY_SIZES = [512, 1024, 2048, 4096]

# Hash algorithm options
HASH_ALGORITHMS = {
    'SHA256': hashes.SHA256,
    'SHA384': hashes.SHA384,
    'SHA512': hashes.SHA512
}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SIGNED_FOLDER'] = SIGNED_FOLDER
app.config['KEYS_FOLDER'] = KEYS_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)

# Store signed files metadata
signed_files = {}

def generate_rsa_keys(key_size=512):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save keys to files
    with open(os.path.join(app.config['KEYS_FOLDER'], 'private_key.pem'), 'wb') as f:
        f.write(private_pem)
    
    with open(os.path.join(app.config['KEYS_FOLDER'], 'public_key.pem'), 'wb') as f:
        f.write(public_pem)
    
    return private_key, public_key

def load_keys():
    try:
        # Load private key
        with open(os.path.join(app.config['KEYS_FOLDER'], 'private_key.pem'), 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load public key
        with open(os.path.join(app.config['KEYS_FOLDER'], 'public_key.pem'), 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        return private_key, public_key
    except FileNotFoundError:
        return generate_rsa_keys()

def sign_file(file_path, private_key, hash_algorithm=hashes.SHA256):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Create signature
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hash_algorithm()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_algorithm()
        )
        
        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        original_filename = os.path.basename(file_path)
        signed_filename = f"{os.path.splitext(original_filename)[0]}_{timestamp}.signed"
        signed_file_path = os.path.join(app.config['SIGNED_FOLDER'], signed_filename)
        
        # Create metadata
        metadata = {
            'original_filename': original_filename,
            'signed_filename': signed_filename,
            'timestamp': timestamp,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'hash_algorithm': hash_algorithm.__name__
        }
        
        # Save signed file with metadata
        with open(signed_file_path, 'wb') as f:
            f.write(data)
            f.write(b'\n---SIGNATURE---\n')
            f.write(json.dumps(metadata).encode('utf-8'))
        
        # Store metadata
        signed_files[signed_filename] = metadata
        
        return signed_file_path, metadata
    except Exception as e:
        print(f"Error signing file: {str(e)}")
        raise

def verify_signature(file_path, public_key, hash_algorithm=hashes.SHA256):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Split content and signature
        content, signature_data = content.split(b'\n---SIGNATURE---\n')
        metadata = json.loads(signature_data)
        signature = base64.b64decode(metadata['signature'])
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                content,
                padding.PSS(
                    mgf=padding.MGF1(hash_algorithm()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_algorithm()
            )
            return True, "Chữ ký hợp lệ", metadata
        except Exception:
            return False, "Chữ ký không hợp lệ", metadata
    except Exception as e:
        return False, f"Lỗi xác thực: {str(e)}", None

@app.route('/')
def index():
    return render_template('index.html', 
                         signed_files=signed_files,
                         key_sizes=KEY_SIZES,
                         hash_algorithms=list(HASH_ALGORITHMS.keys()))

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    try:
        key_size = int(request.form.get('key_size', 512))
        if key_size not in KEY_SIZES:
            return jsonify({
                'success': False,
                'message': f'Kích thước khóa không hợp lệ. Chọn một trong các giá trị: {", ".join(map(str, KEY_SIZES))}'
            })
        
        private_key, public_key = generate_rsa_keys(key_size)
        return jsonify({
            'success': True,
            'message': f'Đã tạo cặp khóa {key_size}-bit thành công'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Lỗi tạo khóa: {str(e)}'
        })

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'message': 'Không tìm thấy file'
        })
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({
            'success': False,
            'message': 'Chưa chọn file'
        })
    
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get hash algorithm from request
        hash_name = request.form.get('hash_algorithm', 'SHA256')
        if hash_name not in HASH_ALGORITHMS:
            return jsonify({
                'success': False,
                'message': f'Thuật toán hash không hợp lệ. Chọn một trong các giá trị: {", ".join(HASH_ALGORITHMS.keys())}'
            })
        
        # Load or generate keys
        private_key, public_key = load_keys()
        
        # Sign file
        signed_file_path, metadata = sign_file(file_path, private_key, HASH_ALGORITHMS[hash_name])
        
        # Clean up original file
        os.remove(file_path)
        
        return jsonify({
            'success': True,
            'message': 'File đã được ký số thành công',
            'metadata': metadata
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Lỗi xử lý file: {str(e)}'
        })

@app.route('/verify', methods=['POST'])
def verify_file():
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'message': 'Không tìm thấy file'
        })
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({
            'success': False,
            'message': 'Chưa chọn file'
        })
    
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get hash algorithm from request
        hash_name = request.form.get('hash_algorithm', 'SHA256')
        if hash_name not in HASH_ALGORITHMS:
            return jsonify({
                'success': False,
                'message': f'Thuật toán hash không hợp lệ. Chọn một trong các giá trị: {", ".join(HASH_ALGORITHMS.keys())}'
            })
        
        # Load public key
        _, public_key = load_keys()
        
        # Verify signature
        is_valid, message, metadata = verify_signature(file_path, public_key, HASH_ALGORITHMS[hash_name])
        
        # Clean up
        os.remove(file_path)
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'message': message,
            'metadata': metadata
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Lỗi xác thực: {str(e)}'
        })

@app.route('/download-key/<key_type>')
def download_key(key_type):
    if key_type not in ['public', 'private']:
        flash('Loại khóa không hợp lệ')
        return redirect(url_for('index'))
    
    key_path = os.path.join(app.config['KEYS_FOLDER'], f'{key_type}_key.pem')
    if not os.path.exists(key_path):
        flash('Không tìm thấy file khóa')
        return redirect(url_for('index'))
    
    return send_file(key_path, as_attachment=True)

@app.route('/download-signed/<filename>')
def download_signed(filename):
    if filename not in signed_files:
        flash('File not found')
        return redirect(url_for('index'))
    
    file_path = os.path.join(app.config['SIGNED_FOLDER'], filename)
    if not os.path.exists(file_path):
        flash('File not found')
        return redirect(url_for('index'))
    
    return send_file(file_path, as_attachment=True)

@app.route('/list-signed')
def list_signed():
    return jsonify({
        'success': True,
        'files': signed_files
    })

if __name__ == '__main__':
    app.run(debug=True) 