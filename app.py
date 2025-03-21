from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
import bcrypt
import pyotp
import qrcode
import io
import base64
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '13122002'
app.config['MYSQL_DB'] = 'auth_db'

mysql = MySQL(app)

# JWT Configuration
app.config["JWT_SECRET_KEY"] = "your_jwt_secret"
jwt = JWTManager(app)


#  Register Route (Check for duplicate users)
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    # Check if user already exists
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    existing_user = cur.fetchone()

    if existing_user:
        cur.close()
        return jsonify({"message": "Username already exists"}), 409  # HTTP 409 Conflict

    # Hash the password and generate 2FA secret
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    secret = pyotp.random_base32()

    # Insert new user
    cur.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)",
                (username, hashed_password, secret))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "User registered successfully", "twofa_secret": secret}), 201


#  Generate QR Code for 2FA
@app.route('/qrcode/<username>', methods=['GET'])
def generate_qr(username):
    cur = mysql.connection.cursor()
    cur.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({"message": "User not found"}), 404

    secret = user[0]
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(username, issuer_name="SecureApp")

    qr = qrcode.make(otp_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return jsonify({"qrcode": img_str})


#  Login Route with 2FA
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    otp = data.get('otp')

    if not username or not password or not otp:
        return jsonify({"message": "All fields are required"}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, password, twofa_secret FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user or not bcrypt.checkpw(password.encode(), user[1].encode()):
        return jsonify({"message": "Invalid credentials"}), 401

    if not pyotp.TOTP(user[2]).verify(otp):
        return jsonify({"message": "Invalid 2FA code"}), 401

    access_token = create_access_token(identity=username, expires_delta=False)
    return jsonify({"access_token": access_token}), 200


#  Add Product (Requires Authentication)
@app.route('/product', methods=['POST'])
@jwt_required()
def add_product():
    data = request.json
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    quantity = data.get('quantity')

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                (name, description, price, quantity))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Product added"}), 201


#  Get All Products (Requires Authentication)
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    cur.close()

    product_list = [{"id": p[0], "name": p[1], "description": p[2], "price": p[3], "quantity": p[4]} for p in products]
    return jsonify(product_list)


# update Product (Requires Authentication)
@app.route('/product/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    data = request.json
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    quantity = data.get('quantity')

    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                (name, description, price, quantity, product_id))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Product updated"}), 200


# Delete Product (Requires Authentication)
@app.route('/product/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Product deleted"}), 200


if __name__ == '__main__':
    app.run(debug=True)
