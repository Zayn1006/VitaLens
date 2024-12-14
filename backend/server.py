from flask import Flask, request, jsonify, session
import joblib
import numpy as np
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import traceback

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///health_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secure_secret_key'  
app.config['SESSION_TYPE'] = 'filesystem'  # session
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True  

db = SQLAlchemy(app)
Session(app)
from flask_cors import CORS

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class HealthData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    height = db.Column(db.Float, nullable=False)
    weight = db.Column(db.Float, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    health_score = db.Column(db.Float, nullable=False)
    suggested_exercise_duration = db.Column(db.String(50))
    suggested_exercise_type = db.Column(db.String(50))
    suggested_exercise_frequency = db.Column(db.String(50))
    suggested_protein_intake = db.Column(db.String(50))
    suggested_carb_intake = db.Column(db.String(50))
    suggested_fat_intake = db.Column(db.String(50))
    suggested_sleep_duration = db.Column(db.String(50))
    checkup_advice = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# 注册用户
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password cannot be empty'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 200
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({'error': 'Server error. Please try again later.'}), 500

# 用户登录路由
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid username or password'}), 401

        session['user_id'] = user.id
        print("Session set for user:", session.get('user_id'))
        return jsonify({'message': 'Login successful', 'user_id': user.id}), 200
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/save_health_data', methods=['POST'])
def save_health_data():
    try:
        print("Request received at /save_health_data")
        print("Session data:", session)
        print("Request cookies:", request.cookies)

        # 检查用户是否已登录
        if 'user_id' not in session:
            print("Unauthorized access: Missing user_id in session.")
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session['user_id']
        data = request.json

        # 类型转换和默认值处理
        def safe_cast(value, to_type, default):
            try:
                return to_type(value)
            except (ValueError, TypeError):
                return default

        data["height"] = safe_cast(data.get("height"), float, 0.0)
        data["weight"] = safe_cast(data.get("weight"), float, 0.0)
        data["age"] = safe_cast(data.get("age"), int, 0)
        data["exercise_hours"] = safe_cast(data.get("exercise_hours"), float, 0.0)
        data["sleep_hours"] = safe_cast(data.get("sleep_hours"), float, 0.0)
        data["systolic_bp"] = safe_cast(data.get("systolic_bp"), float, 0.0)
        data["diastolic_bp"] = safe_cast(data.get("diastolic_bp"), float, 0.0)
        data["smoking"] = safe_cast(data.get("smoking"), int, 0)
        data["drinking"] = safe_cast(data.get("drinking"), int, 0)
        data["sex"] = data.get("sex", "Unknown")
        data["health_status"] = data.get("health_status", "Unknown")
        data["diet_habits"] = data.get("diet_habits", "Unknown")
        data["menstrual_cycle"] = data.get("menstrual_cycle", "Unknown")

        # 计算 BMI
        height_m = data["height"] / 100  # Convert height to meters
        weight_kg = data["weight"]
        data["bmi"] = round(weight_kg / (height_m ** 2), 2) if height_m > 0 else 0

        # 加载模型
        model_dir = './'  # 修改为实际模型路径
        health_score_model = joblib.load(model_dir + 'health_score_model.pkl')
        exercise_duration_model = joblib.load(model_dir + 'suggested_exercise_duration_model.pkl')
        exercise_type_model = joblib.load(model_dir + 'suggested_exercise_type_model.pkl')
        exercise_frequency_model = joblib.load(model_dir + 'suggested_exercise_frequency_model.pkl')
        protein_intake_model = joblib.load(model_dir + 'suggested_protein_intake_model.pkl')
        carb_intake_model = joblib.load(model_dir + 'suggested_carb_intake_model.pkl')
        fat_intake_model = joblib.load(model_dir + 'suggested_fat_intake_model.pkl')
        sleep_duration_model = joblib.load(model_dir + 'suggested_sleep_duration_model.pkl')
        checkup_advice_model = joblib.load(model_dir + 'checkup_advice_model.pkl')

        # 转换数据为 DataFrame
        input_data = pd.DataFrame([data])

        # 确保输入数据与训练特征一致
        input_data_encoded = pd.get_dummies(input_data)
        all_columns = joblib.load(model_dir + 'columns.pkl')  # 训练时保存的特征列

        # 添加缺失的列并按顺序排列
        for col in all_columns:
            if col not in input_data_encoded.columns:
                input_data_encoded[col] = 0  # 对缺失列填充默认值 0
        input_data_encoded = input_data_encoded[all_columns]  # 按顺序排列列

        # 生成预测
        health_score = health_score_model.predict(input_data_encoded)[0]
        exercise_duration = exercise_duration_model.predict(input_data_encoded)[0]
        exercise_type = exercise_type_model.predict(input_data_encoded)[0]
        exercise_frequency = exercise_frequency_model.predict(input_data_encoded)[0]
        protein_intake = protein_intake_model.predict(input_data_encoded)[0]
        carb_intake = carb_intake_model.predict(input_data_encoded)[0]
        fat_intake = fat_intake_model.predict(input_data_encoded)[0]
        sleep_duration = sleep_duration_model.predict(input_data_encoded)[0]
        checkup_advice = checkup_advice_model.predict(input_data_encoded)[0]

        # 保存健康数据到数据库
        health_data = HealthData(
            user_id=user_id,
            height=data['height'],
            weight=data['weight'],
            age=data['age'],
            health_score=health_score,
            suggested_exercise_duration=exercise_duration,
            suggested_exercise_type=exercise_type,
            suggested_exercise_frequency=exercise_frequency,
            suggested_protein_intake=protein_intake,
            suggested_carb_intake=carb_intake,
            suggested_fat_intake=fat_intake,
            suggested_sleep_duration=sleep_duration,
            checkup_advice=checkup_advice
        )
        db.session.add(health_data)
        db.session.commit()

        # 返回预测结果
        return jsonify({
            'bmi': data["bmi"],
            'health_score': round(health_score, 2),
            'suggested_exercise_duration': exercise_duration,
            'suggested_exercise_type': exercise_type,
            'suggested_exercise_frequency': exercise_frequency,
            'suggested_protein_intake': protein_intake,
            'suggested_carb_intake': carb_intake,
            'suggested_fat_intake': fat_intake,
            'suggested_sleep_duration': sleep_duration,
            'checkup_advice': checkup_advice
        })
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

# 获取用户历史数据
@app.route('/history', methods=['GET'])
def history():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session['user_id']
        history_data = HealthData.query.filter_by(user_id=user_id).all()

        if not history_data:
            return jsonify({'message': 'No history data available'}), 200

        # Include BMI calculation and exclude unnecessary fields
        history = [
            {
                'timestamp': h.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'height': h.height,
                'weight': h.weight,
                'age': h.age,
                'health_score': h.health_score,
                'bmi': round(h.weight / ((h.height / 100) ** 2), 2) if h.height > 0 else None
            }
            for h in history_data
        ]

        return jsonify({'history': history}), 200
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/logout', methods=['POST'])
def logout():
    try:
        session.clear()
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

# 用户认证路由
@app.route('/auth', methods=['GET'])
def auth():
    if 'user_id' in session:
        return jsonify({'message': 'Authenticated'}), 200
    return jsonify({'error': 'Unauthorized'}), 401

@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)