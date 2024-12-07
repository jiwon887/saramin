from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
import datetime
from mysql.connector import Error


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234@localhost:3306/job_posting'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 유저 모델
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)

# 채용 공고 모델
class Posting(db.Model):
    company = db.relationship('Company', backref='posts')

    posting_id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.company_id'))
    title = db.Column(db.String(255), nullable=False)
    career = db.Column(db.String(255), nullable=False)
    education = db.Column(db.String(255), nullable=False)
    deadline = db.Column(db.Date, nullable=False)
    skill = db.Column(db.String(255), nullable=False)


# 회사 모델
class Company(db.Model):
    company_id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    company_name = db.Column(db.String(255), unique=True ,nullable=False)
    company_category = db.Column(db.String(255), nullable=False)
    company_place = db.Column(db.String(255), nullable=False)
    company_url = db.Column(db.String(255), nullable=False)

# 북마크 모델
class Bookmark(db.Model):
    user = db.relationship('User', backref='posts')
    posting = db.relationship('Posting', backref='posts')

    bookmark_id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=True)
    posting_id = db.Column(db.Integer, db.ForeignKey('posting.posting_id'), nullable=True)

# 대기업 모델
class Top(db.Model):
    curation_company_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    curation_company_name = db.Column(db.String(255), unique=True, nullable=True)
    curation_company_type = db.Column(db.String(255), nullable=True)
    curation_company_year = db.Column(db.String(255), nullable=True)
    curation_company_genre = db.Column(db.String(255), nullable=True)


# 지원 내역 모델
class Application(db.Model):
    user = db.relationship('User', backref='posts')
    posting = db.relationship('Posting', backref='posts')

    application_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=True)
    posting_id = db.Column(db.Integer, db.ForeignKey('posting.posting_id'), nullable=True)
    applied_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)



# 토큰 설정
app.config.update(
        DEBUG=True,
        JWT_SECRET_KEY = "String"
)

jwt = JWTManager(app)


# 회원관리
# 회원가입 처리
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    name = data['name']
    email = data['email']
    password = data['password']
    hashed_password = generate_password_hash(password)

    # 중복된 이메일 가입 처리
    chk = User.query.filter.by(email=email).first()
    if chk :
        return jsonify({"message : 이미 가입된 이메일"}), 400


    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "회원 가입 완료"}), 201

# 로그인 처리
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data['email']
    password = data['password']
    
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=email)
        return jsonify(message="로그인 성공", access_token=access_token), 200

    return jsonify({"message": "로그인 실패: 잘못된 이메일 또는 비밀번호"}), 401

# 사용자 정보 수정
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    user = User.query.get(user_id)
    if user:
        data = request.json
        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        db.session.commit()
        return jsonify({"message": "회원 정보 수정 완료"}), 200

    return jsonify({"message": "사용자를 찾을 수 없습니다."}), 404


# 회원 탈퇴
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "회원 탈퇴 완료"}), 200

    return jsonify({"message": "사용자를 찾을 수 없습니다."}), 404



# 지원하기 기능
# 지원하기 (POST /applications)
@app.route('/api/applications', methods=['POST'])
@jwt_required()
def apply():
    data = request.json
    user_id = data.get('user_id')
    posting_id = data.get('posting_id')

    # 중복 지원 체크
    existing_application = Application.query.filter_by(user_id=user_id, posting_id=posting_id).first()
    if existing_application:
        return jsonify({"message": "이미 해당 공고에 지원하셨습니다."}), 400

    # 지원 정보 저장
    application = Application(user_id=user_id, posting_id=posting_id)
    db.session.add(application)
    db.session.commit()

    return jsonify({"message": "지원이 완료되었습니다.", "application_id": application.application_id}), 201


# 지원 내역 조회 (GET /applications)
@app.route('/api/applications', methods=['GET'])
@jwt_required()
def get_applications():
    user_id = request.args.get('user_id')
    status = request.args.get('status')
    sort_order = request.args.get('sort', 'desc')  # 정렬 순서 (기본값: 내림차순)

    query = Application.query.filter_by(user_id=user_id)

    # 상태별 필터링
    if status:
        query = query.filter_by(status=status)

    # 날짜별 정렬
    if sort_order == 'asc':
        query = query.order_by(Application.applied_at.asc())
    else:
        query = query.order_by(Application.applied_at.desc())

    applications = query.all()
    result = [
        {
            "application_id": app.application_id,
            "posting_id": app.posting_id,
            "status": app.status,
            "applied_at": app.applied_at,
            "resume": app.resume
        }
        for app in applications
    ]

    return jsonify(result), 200


# 지원 취소 (DELETE /applications/:id)
@app.route('/api/applications/<int:application_id>', methods=['DELETE'])
@jwt_required()
def cancel_application(application_id):
    application = Application.query.get(application_id)
    if not application:
        return jsonify({"message": "지원 내역을 찾을 수 없습니다."}), 404

    # 지원 취소 가능 여부 확인
    if application.status != "submitted":
        return jsonify({"message": "해당 지원은 취소할 수 없습니다."}), 400

    # 상태 업데이트
    application.status = "cancelled"
    db.session.commit()

    return jsonify({"message": "지원이 취소되었습니다."}), 200


# 공고 

# 채용 공고 조회 (GET /jobs)
@app.route('/jobs', methods=['GET'])
def view_post():
    postings = Posting.query.all()
    result = [
        {
            "posting_id": posting.posting_id,
            "company_id": posting.company_id,
            "title": posting.title,
            "career": posting.career,
            "education": posting.education,
            "deadline": posting.deadline,
            "skill": posting.skill
        }
        for posting in postings
    ]
    return jsonify(result), 200


# 검색
@app.route('/jobs', methods=['GET'])
def search_post():
    company_id = request.args.get('company_id')
    title = request.args.get('title')
    career = request.args.get('career')
    education = request.args.get('education')
    deadline = request.args.get('deadline')
    skill = request.args.get('skill')

    query = Posting.query

    if company_id:
        query = query.filter_by(company_id=company_id.contains(company_id))
    if title:
        query = query.filter(Posting.title.contains(title))  # 부분 일치 검색
    if career:
        query = query.filter_by(career=career.contains(career))
    if education:
        query = query.filter_by(education=education.contains(education))
    if deadline:
        query = query.filter_by(deadline=deadline)
    if skill:
        query = query.filter(Posting.skill.contains(skill))  # 부분 일치 검색

    postings = query.all()

    result = [
        {
            "posting_id": posting.posting_id,
            "company_id": posting.company_id,
            "title": posting.title,
            "career": posting.career,
            "education": posting.education,
            "deadline": posting.deadline,
            "skill": posting.skill
        }
        for posting in postings
    ]
    return jsonify(result), 200




if __name__ == '__main__':
    app.run(debug=True)