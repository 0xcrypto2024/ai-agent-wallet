import os
import secrets
import base64
import hashlib  # For password hashing
import pyotp  # For Google Authenticator
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, jsonify, request, g
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from datetime import timedelta
from eth_account import Account
import psycopg2  # Or your preferred database library
from dotenv import load_dotenv
from web3 import Web3


load_dotenv()
DATABASE_URL = os.environ.get("DATABASE_URL")  # Now get the value!
print(f"DATABASE_URL: {DATABASE_URL}") 

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "migrations/versions")

# --- Configure Web3 ---
WEB3_PROVIDER_URI = os.environ.get("WEB3_PROVIDER_URI") # Example: "http://127.0.0.1:8545/"  (Ganache, for example)
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URI))  # Initialize Web3

app = Flask(__name__)

# --- Password Hashing ---
def hash_password(password, salt):
    salted_password = salt.encode() + password.encode()
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def parse_timedelta(time_str):
    """Parses a time string (e.g., '30m', '1h', '1d') into a timedelta object."""
    try:
        amount, unit = int(time_str[:-1]), time_str[-1].lower()
        if unit == 'm':
            return timedelta(minutes=amount)
        elif unit == 'h':
            return timedelta(hours=amount)
        elif unit == 'd':
            return timedelta(days=amount)
        else:
            raise ValueError("Invalid time unit. Use 'm', 'h', or 'd'.")
    except (ValueError, IndexError):
        raise ValueError("Invalid time string format. Use like '30m', '1h', or '1d'.")

def apply_migrations(cursor):
    """Applies database migrations."""
    try:
        # Check if applied_migrations table exists, create if not
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS applied_migrations (
                version INTEGER PRIMARY KEY,  -- Use version numbers
                migration_name TEXT UNIQUE NOT NULL  -- Store the filename 
            );
        """)

        # Get current version. Could also store latest version in a text file, environment variable, etc.
        cursor.execute("SELECT MAX(version) FROM applied_migrations;")
        current_version = cursor.fetchone()[0]
        current_version = current_version if current_version is not None else 0


    except psycopg2.Error as e:
        print(f"Migration table error: {e}")
        raise

    migration_files = sorted([f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql")])
    for migration_file in migration_files:
        # Extract migration version from filename (e.g. 001, 002, etc.)
        try:
            version = int(migration_file.split("_")[0])
        except (ValueError, IndexError):
            print(f"Skipping invalid migration file: {migration_file}")
            continue  # skip if cannot extract version
        if version > current_version:
            try:
                migration_path = os.path.join(MIGRATIONS_DIR, migration_file)
                with open(migration_path, "r") as f:
                    sql = f.read()
                    print(f"Applying migration: {migration_file}")
                    cursor.execute(sql)
                    # Record successful migration
                    cursor.execute("INSERT INTO applied_migrations (version, migration_name) VALUES (%s, %s)", (version, migration_file))
            except psycopg2.Error as e:
                print(f"Error applying migration {migration_file}: {e}")
                raise

def generate_mfa_secret():
    """Generates a new base32 secret for MFA."""
    return pyotp.random_base32()

def get_db():
    if 'db' not in g:
        database_uri = os.environ.get("DATABASE_URL")
        if not database_uri:
            raise ValueError("DATABASE_URL not set")  # Raise an error, do not fail silently.
        try:
            g.db = psycopg2.connect(database_uri, sslmode='disable')
        except psycopg2.Error as e:
            print(f"Database connection error: {e}")
            raise  # Very important for debugging!

        with g.db.cursor() as cursor:
            apply_migrations(cursor) # Apply migrations when establishing the connection
            g.db.commit()
    return g.db

# Example of decryption (adapt to your needs):
def decrypt_private_key(encrypted_key_with_salt, user_password):
    try:

        encrypted_private_key, salt_hex  = encrypted_key_with_salt.split(":",1)
        salt = bytes.fromhex(salt_hex)
        kdf = PBKDF2HMAC( # Same setting as encryption
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        fernet_key = base64.urlsafe_b64encode(kdf.derive(user_password.encode()))
        f = Fernet(fernet_key)
        private_key_bytes = f.decrypt(encrypted_private_key.encode())
        private_key = private_key_bytes.decode()

        return private_key
    except Exception as e:
        print("failed to decrypt private key: {e}")
        return None

# --- Helper Function to Get Private Key (adapt as needed, or integrate with your load_wallet function)
def get_private_key(username, password, mfa_code, address):

    db = get_db()
    cursor = db.cursor()
    try:
        print(f"Querying for username: {username}, address: {address}") 
        cursor.execute("""SELECT encrypted_private_key, w.salt, mfa_secret
                          FROM wallets w JOIN users u ON w.user_id = u.user_id
                          WHERE u.username = %s AND w.address = %s;""", (username, address))
        
        result = cursor.fetchone()
        print(f"Result from database: {result}")  # What did the query return?
        if not result:
            return None  # Wallet not found or user does not own wallet with given address.

        encrypted_private_key, salt, mfa_secret = result
        print(f"Encrypted Key: {encrypted_private_key}, Salt: {salt}, MFA Secret: {mfa_secret}") 
        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(mfa_code):  # Verify MFA
            return None

        encrypted_private_key_with_salt = f"{encrypted_private_key}:{salt}" # Recreate the salt:key combination for decryption
        private_key = decrypt_private_key(encrypted_private_key_with_salt, password)  # Decrypt
        print(f"Decrypted Private Key: {private_key}")  # Print after decryption
        return private_key

    except Exception as e:
        print(f"Error in get_private_key: {e}")
        return None

    finally:
        cursor.close()


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Get the expiration time from the environment variable
expires_str = os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", "30m") # Default is 30 minutes


try:
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = parse_timedelta(expires_str)
except ValueError as e:
    print(f"Error parsing JWT expiration time: {e}")
    # Handle the error appropriately (e.g., exit, use a default value)



# JWT Configuration (replace with your own secret key)
app.config["JWT_SECRET_KEY"] = secrets.token_urlsafe(32)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)  # Expires in 30 minutes
jwt = JWTManager(app)

# User registration
@app.route('/api/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # 1. Check if username already exists.  Important for uniqueness
        cursor.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        if cursor.fetchone():  # If a row is returned, the username exists
            return jsonify({"error": "Username already exists"}), 400
        # 2. Hash the password  Don't store passwords in plain text!
        salt = secrets.token_hex(16) # generate a salt.
        hashed_password = hash_password(password, salt)
        # 3. Insert the new user into the database  Use parameterized query to prevent SQL injection.
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s) RETURNING user_id", (username, hashed_password, salt))
        db.commit()
        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        db.rollback()
        print(f"Registration error: {e}")  # Print exception for debugging
        return jsonify({"error": "Failed to register user"}), 500

    finally: # Always close the cursor in a finally block
        cursor.close()



# User Login (generates a JWT)
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"msg": "Bad username or password"}), 401  # Incorrect credentials

    db = get_db()
    cursor = db.cursor()

    try:
        # Retrieve user information, including the salt
        cursor.execute("SELECT user_id, password_hash, salt FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"msg": "Bad username or password"}), 401  # User not found

        user_id, stored_password_hash, salt = user # get the user details from the database


        # Hash the provided password with the retrieved salt
        hashed_password = hash_password(password, salt)


        # Compare the hashed password with the stored hash
        if hashed_password != stored_password_hash:  # Incorrect password

            return jsonify({"msg": "Bad username or password"}), 401

        # If credentials are valid, create and return a JWT
        access_token = create_access_token(identity=username)  # identity=user_id is more secure
        return jsonify(access_token=access_token)


    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

    finally:
        cursor.close() # very important!


# --- Create Wallet Route ---
@app.route('/api/create_wallet', methods=['POST'])
@jwt_required()
def create_wallet():
    user_password = request.json.get('password')  # Get password from request

    if not user_password:  # Basic validation
        return jsonify({"error": "Password is required"}), 400

    db = get_db()
    cursor = db.cursor()
    try:
        username = get_jwt_identity()  # Get the username from the JWT
        print(f"Username from JWT: {username}")

        # --- Key Derivation and Encryption ---
        salt = os.urandom(16)  # Generate a secure random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Key length for Fernet
            salt=salt,
            iterations=100000,  # Adjust iterations for security/performance
        )

        key = base64.urlsafe_b64encode(kdf.derive(user_password.encode()))  # Derive key
        f = Fernet(key)

        # --- Account Creation and Encryption ---
        account = Account.create()
        private_key = account.key.hex()
        encrypted_private_key = f.encrypt(private_key.encode()).decode() # Encrypt and store as string


        # --- Database Insertion ---
        try:
            query = """
                    INSERT INTO wallets (address, encrypted_private_key, salt, user_id) 
                    VALUES (%s, %s, %s, (SELECT user_id FROM users WHERE username = %s))
                    """
            print(f"SQL Query about to be executed: {cursor.mogrify(query,(account.address, encrypted_private_key, salt.hex(), username))}")  # Print the query *before* execution

            cursor.execute(query, (account.address, encrypted_private_key, salt.hex(), username))
            db.commit()  # Commit transaction after successful execution

            return jsonify({"address": account.address}), 201

        except Exception as e:
            db.rollback()  # Rollback if any error during insertion
            print(f"Database Insertion Error: {e}")  # Print *detailed* exception info
            return jsonify({"error": "Failed to insert into database"}), 500  # Generic message to client


    except Exception as e:  # Handle exceptions properly
        print(f"Error creating wallet: {e}") # Log the error for debugging
        return jsonify({"error": "Failed to create wallet"}), 500 # Don't reveal specific error details in production responses

    finally:
        cursor.close()  # Important to close cursor even if error occurs.

# Caution: Only call this method when MFA needs to be updated or setup. 
@app.route('/api/setup_mfa', methods=['POST'])
@jwt_required()
def setup_mfa():
    """Sets up MFA for the logged-in user."""
    db = get_db()
    cursor = db.cursor()
    try:
        username = get_jwt_identity()

        # 1. Check if user already has MFA enabled.
        cursor.execute("SELECT mfa_secret FROM users WHERE username = %s", (username,))
        existing_secret = cursor.fetchone()
        if existing_secret and existing_secret[0]: # Check both tuple and value.
            return jsonify({"error": "MFA already setup for this user"}), 400

        # 2. Generate a new MFA secret
        mfa_secret = generate_mfa_secret()

        # 3. Store the MFA secret in the database (update the users table).
        cursor.execute("UPDATE users SET mfa_secret = %s WHERE username = %s", (mfa_secret, username))
        db.commit()

        # 4. Generate and return the provisioning URI for the authenticator app
        provisioning_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=username, issuer_name="Agent-Wallet")
        return jsonify({"mfa_uri": provisioning_uri}), 201  # 201 Created


    except Exception as e:
        db.rollback()
        print(f"MFA setup error: {e}")
        return jsonify({"error": "Failed to set up MFA"}), 500

    finally:
        cursor.close()


@app.route('/api/load_wallet', methods=['POST'])
@jwt_required()
def load_wallet():

    username = get_jwt_identity()
    user_password = request.json.get('password')
    mfa_code = request.json.get('mfa_code')  # Get the MFA code from the request

    if not user_password or not mfa_code: # require both
        return jsonify({"error": "Password and MFA code are required"}), 400
    
    address = request.json.get('address')
    if not address:
       return jsonify({"error": "address is required"}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Retrieve wallet and MFA information
        cursor.execute(
            "SELECT encrypted_private_key, w.salt, mfa_secret FROM wallets w JOIN users u ON w.user_id = u.user_id WHERE u.username = %s AND w.address = %s", # Address needed here.
            (username,address), # Address parameter was missing.
        )
        wallet_data = cursor.fetchone()

        if not wallet_data:
            return jsonify({"error": "Wallet not found for this user"}), 404

        encrypted_private_key, salt_hex, mfa_secret = wallet_data  # Retrieve mfa_secret

        # --- MFA Verification ---
        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(mfa_code):
            return jsonify({"error": "Invalid MFA code"}), 401  # Unauthorized

        # --- Decrypt only after successful MFA verification ---
        encrypted_private_key_with_salt = f"{encrypted_private_key}:{salt_hex}" # recreate this.
        private_key = decrypt_private_key(encrypted_private_key_with_salt, user_password)

        if private_key:
            account = Account.from_key(bytes.fromhex(private_key))
            return jsonify({"address": account.address}), 200
        else:
            return jsonify({"error": "Incorrect password or decryption failed"}), 401


    except Exception as e:
        print(f"Error loading wallet: {e}")  # Print exception to server logs.
        return jsonify({"error": "Failed to load wallet"}), 500

    finally:
        cursor.close()

# --- Native Token Transfer ---
@app.route('/api/transfer', methods=['POST'])
@jwt_required()
def transfer():
    username = get_jwt_identity()
    password = request.json.get('password')
    mfa_code = request.json.get('mfa_code')
    to_address = request.json.get('to_address')
    amount = request.json.get('amount')  # Amount in wei (smallest unit of ether)
    wallet_address = request.json.get('address') # The user's wallet address.

    if not all([password, mfa_code, to_address, amount, wallet_address]):  # Essential validation!
        return jsonify({"error": "Missing required parameters"}), 400


    try:
        amount = int(amount) # should be int or decimal, for example wei.
    except ValueError as e:
        print(f"Cannot convert {amount=} to number")
        return jsonify({"error": "Amount must be a valid number"}), 400

    # Get user's private key. Handle None if retrieval fails.
    private_key = get_private_key(username, password, mfa_code, wallet_address)

    if private_key is None: # Handle case where private key could not be retrieved
        return jsonify({"error": "Failed to access wallet"}), 401  # Unauthorized


    try:
        account = Account.from_key(bytes.fromhex(private_key)) #  Use private key to set up account
        nonce = w3.eth.get_transaction_count(account.address)
        # Build the transaction
        tx = {
            'nonce': nonce,
            'to': to_address,
            'value': amount,
            'gas': 21000,  # Adjust gas as needed
            'gasPrice': w3.eth.gas_price, # Fetch current gas price from provider.
            'chainId': w3.eth.chain_id
        }

        # Sign the transaction
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)

        # Send the transaction
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)


        return jsonify({"tx_hash": tx_hash.hex()}), 201 # Return transaction hash

    except Exception as e:  # Handle web3 or other exceptions properly
        print(f"Error sending transaction: {e}")  # Log details for debugging
        return jsonify({"error": "Failed to send transaction"}), 500  # Generic message to the client



# --- Smart Contract Interaction (Example) ---
@app.route('/api/contract_call', methods=['POST'])
@jwt_required()
def contract_call():
    username = get_jwt_identity()
    password = request.json.get('password')
    mfa_code = request.json.get('mfa_code')

    contract_address = request.json.get('contract_address')
    contract_abi = request.json.get('contract_abi')
    function_name = request.json.get('function_name')
    function_args = request.json.get('function_args', [])  # Allow empty args
    wallet_address = request.json.get('address') #  Address from which to send the tx.

    # Essential validation
    if not all([password, mfa_code, contract_address, contract_abi, function_name, wallet_address]):
        return jsonify({"error": "Missing required parameters"}), 400

    # Private key retrieval (handle MFA, decryption, errors)
    private_key = get_private_key(username, password, mfa_code, wallet_address)
    if private_key is None:
        return jsonify({"error": "Failed to access wallet"}), 401

    try:

        account = Account.from_key(bytes.fromhex(private_key))
        # Set up the contract object
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)


        # Get the contract function
        contract_function = contract.functions[function_name](*function_args) # use the function arguments

        # Build, sign and send transaction

        tx = contract_function.buildTransaction({'from':account.address,'nonce':w3.eth.getTransactionCount(account.address)}) # Get nonce
        signed_txn = w3.eth.account.signTransaction(tx,private_key=private_key)  # Sign the transaction
        tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)


        return jsonify({"tx_hash": tx_hash.hex()}), 201

    except Exception as e:  # Catch web3 or contract-related exceptions
        print(f"Error interacting with contract: {e}") # Important: Log the detailed error!
        return jsonify({"error": "Failed to interact with contract"}), 500


# --- ERC20 Token Transfer ---
@app.route('/api/transfer_erc20', methods=['POST'])
@jwt_required()
def transfer_erc20():

    username = get_jwt_identity()
    password = request.json.get('password')
    mfa_code = request.json.get('mfa_code')
    token_address = request.json.get('token_address')
    to_address = request.json.get('to_address')
    amount = request.json.get('amount')
    wallet_address = request.json.get('address') # Wallet making the transfer

    if not all([password, mfa_code, token_address, to_address, amount, wallet_address]):
        return jsonify({"error": "Missing parameters"}), 400

    private_key = get_private_key(username, password, mfa_code, wallet_address)  # Private key and mfa verification
    if private_key is None:
        return jsonify({"error": "Failed to load wallet"}), 401

    try:
        account = Account.from_key(bytes.fromhex(private_key))
        # --- Standard ERC20 ABI (you can make this a constant) ---
        erc20_abi = [
            {"constant": False,"inputs": [{"name": "_to","type": "address"},{"name": "_value","type": "uint256"}],"name": "transfer","outputs": [{"name": "","type": "bool"}],"payable": False,"stateMutability": "nonpayable","type": "function"} # transfer function
        ]
        contract = w3.eth.contract(address=token_address, abi=erc20_abi)
        transfer_fn = contract.functions.transfer(to_address, amount) # set up the transfer function here with params

         # Build the transaction
        transaction = transfer_fn.buildTransaction({
            'from': account.address,
            'gas': 70000,  # Adjust gas as needed (get gas estimate for better accuracy)
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.getTransactionCount(account.address)
        })

        # Sign the transaction
        signed_tx = w3.eth.account.signTransaction(transaction, private_key)

        # Send transaction
        tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
        return jsonify({"tx_hash": tx_hash.hex()}), 201


    except Exception as e:
        print(f"ERC20 transfer error: {e}")
        return jsonify({"error": "Failed to send ERC20 token"}), 500



if __name__ == "__main__":
    app.run(debug=True)  # Start the Flask development server
