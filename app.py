from flask import Flask, jsonify, request
import sqlite3
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = 'kavya-primetrade-secret-key' 
jwt = JWTManager(app)

def get_db_connection():
    conn = sqlite3.connect('primetrade_db.sqlite')
    conn.row_factory = sqlite3.Row
    return conn

def setup_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            user_username TEXT,
            FOREIGN KEY(user_username) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

setup_database()

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Primetrade API is successfully running with SQLite!"})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required!"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists!"}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required!"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        # FIX: ಇಲ್ಲಿ ಡಿಕ್ಷನರಿ ಬದಲು ಕೇವಲ 'username' ಅನ್ನು ಸ್ಟ್ರಿಂಗ್ ಆಗಿ ಕಳಿಸುತ್ತಿದ್ದೇವೆ
        access_token = create_access_token(identity=user['username'])
        return jsonify({
            "message": "Login successful!", 
            "access_token": access_token
        }), 200
    else:
        return jsonify({"error": "Invalid username or password!"}), 401

@app.route('/tasks', methods=['POST'])
@jwt_required()
def create_task():
    current_user = get_jwt_identity() # ಈಗ ಇದು ನೇರವಾಗಿ ಸ್ಟ್ರಿಂಗ್ ಆಗಿರುತ್ತದೆ
    data = request.get_json()
    title = data.get('title')
    description = data.get('description', '')

    if not title:
        return jsonify({"error": "Task title is required!"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tasks (title, description, user_username) VALUES (?, ?, ?)",
                   (title, description, current_user))
    conn.commit()
    conn.close()
    return jsonify({"message": "Task created successfully!"}), 201

@app.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()
    tasks = cursor.execute("SELECT * FROM tasks WHERE user_username = ?", (current_user,)).fetchall()
    conn.close()

    task_list = [{"id": task["id"], "title": task["title"], "description": task["description"], "status": task["status"]} for task in tasks]
    return jsonify(task_list), 200

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    current_user = get_jwt_identity()
    data = request.get_json()
    new_status = data.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()
    task = cursor.execute("SELECT * FROM tasks WHERE id = ? AND user_username = ?", (task_id, current_user)).fetchone()
    
    if not task:
        return jsonify({"error": "Task not found!"}), 404

    cursor.execute("UPDATE tasks SET status = ? WHERE id = ?", (new_status, task_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Task updated successfully!"}), 200

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    current_user = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()
    task = cursor.execute("SELECT * FROM tasks WHERE id = ? AND user_username = ?", (task_id, current_user)).fetchone()
    
    if not task:
        return jsonify({"error": "Task not found!"}), 404

    cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Task deleted successfully!"}), 200

if __name__ == '__main__':
    app.run(debug=True)