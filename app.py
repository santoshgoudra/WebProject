from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import base64
import os
import logging

app = Flask(__name__)

# AES key must be exactly 16, 24, or 32 bytes long
key = b'This_is_16bytes!'
logging.basicConfig(level=logging.DEBUG)

# Configure upload folder for file storage
app.config['UPLOAD_FOLDER'] = 'uploads/'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# In-memory store for messages and files (this is just for demo purposes)
message_store = {}

# Helper function to encode data in base64
def base64_encode(data):
    return base64.b64encode(data).decode('utf-8')

# Helper function to decode data from base64
def base64_decode(data):
    return base64.b64decode(data)

# Function to encrypt message or file content
def encrypt_message(plaintext):
    cipher = AES.new(key, AES.MODE_CBC)  # Create a new AES cipher using CBC mode
    iv = cipher.iv  # Get the 16-byte IV
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))  # Encrypt with padding
    iv_encoded = base64_encode(iv)  # Base64 encode the IV
    ct_encoded = base64_encode(ct_bytes)  # Base64 encode the ciphertext
    logging.debug(f"Encryption successful. IV: {iv_encoded}, Ciphertext: {ct_encoded}")
    return iv_encoded, ct_encoded

# Function to decrypt message or file content
def decrypt_message(iv, ciphertext):
    try:
        iv_decoded = base64_decode(iv)  # Base64 decode the IV
        ct_decoded = base64_decode(ciphertext)  # Base64 decode the ciphertext
        cipher = AES.new(key, AES.MODE_CBC, iv_decoded)  # Initialize cipher with the decoded IV
        pt = unpad(cipher.decrypt(ct_decoded), AES.block_size)  # Decrypt and unpad the plaintext
        return pt.decode('utf-8')  # Return decoded plaintext
    except (ValueError, KeyError) as e:
        logging.error(f"Decryption failed. IV: {iv}, Error: {str(e)}")
        return "Decryption failed"

# Route for home page (index)
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle sending a message or uploading a file
@app.route('/send_message_or_file', methods=['POST'])
def send_message_or_file():
    device_id = request.form.get('device_id')
    message = request.form.get('message', '')
    file = request.files.get('file')

    if not device_id:
        return jsonify({'error': 'Device ID is required'}), 400

    if device_id not in message_store:
        message_store[device_id] = {}

    iv = None  # Initialize IV

    # Encrypt message if provided
    if message:
        iv, encrypted_message = encrypt_message(message)
        message_store[device_id]['message'] = encrypted_message
        message_store[device_id]['iv'] = iv  # Store the IV used for the message
        logging.debug(f"Message IV stored for device {device_id}: {iv}")

    # Handle file upload and encryption
    if file:
        filename = secure_filename(file.filename)
        if not filename:
            return jsonify({'error': 'No file selected'}), 400

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)  # Save the file
        logging.debug(f"File saved at: {file_path}")

        # Encrypt the file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        file_iv, encrypted_file_data = encrypt_message(file_data.decode('latin-1'))  # Encrypt file data
        encrypted_file_path = file_path + '.enc'

        with open(encrypted_file_path, 'wb') as f:
            f.write(base64_decode(encrypted_file_data))  # Save the encrypted file

        message_store[device_id]['file'] = os.path.basename(encrypted_file_path)
        message_store[device_id]['file_iv'] = file_iv  # Store the IV used for the file
        message_store[device_id]['file_uploaded'] = True
        logging.debug(f"File IV stored for device {device_id}: {file_iv}")

        if iv is None:
            iv = file_iv
    else:
        message_store[device_id]['file_uploaded'] = False

    logging.debug(f"Returning IV for device {device_id}: {iv}")
    return jsonify({'iv': iv})

# Route to handle receiving and decrypting a message or file
@app.route('/receive_message_or_file', methods=['POST'])
def receive_message_or_file():
    data = request.get_json()
    device_id = data.get('device_id')
    iv = data.get('iv')

    logging.debug(f"Received request to decrypt for device {device_id} with IV: {iv}")

    if not device_id or not iv:
        return jsonify({'error': 'Device ID and IV are required'}), 400

    if device_id not in message_store:
        return jsonify({'error': 'Invalid device ID'}), 400

    response = {}

    # Decrypt the message
    if 'message' in message_store[device_id]:
        stored_iv = message_store[device_id].get('iv')
        if iv == stored_iv:
            decrypted_message = decrypt_message(iv, message_store[device_id]['message'])
            response['plaintext'] = decrypted_message
            logging.debug(f"Message decrypted for device {device_id}")
        else:
            return jsonify({'error': 'Invalid IV for message decryption'}), 400

    # Decrypt the file if uploaded
    if message_store[device_id].get('file_uploaded'):
        file_iv = message_store[device_id].get('file_iv')
        if iv == file_iv:
            encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], message_store[device_id]['file'])
            decrypted_file_path = encrypted_file_path.replace('.enc', '')

            with open(encrypted_file_path, 'rb') as f:
                encrypted_file_data = f.read()

            decrypted_file_data = decrypt_message(file_iv, base64_encode(encrypted_file_data))

            if decrypted_file_data != "Decryption failed":
                with open(decrypted_file_path, 'wb') as f:
                    f.write(decrypted_file_data.encode('latin-1'))  # Save the decrypted file

                response['file_name'] = os.path.basename(decrypted_file_path)
                logging.debug(f"File decrypted and saved at {decrypted_file_path} for device {device_id}")
            else:
                return jsonify({'error': 'File decryption failed'}), 400
        else:
            return jsonify({'error': 'Invalid IV for file decryption'}), 400

    return jsonify(response)

# Route to download the decrypted file
@app.route('/download_file/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    logging.debug(f"Download request for file: {file_path}")

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5500)
