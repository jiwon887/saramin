from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
import datetime
from mysql.connector import Error
from flask_restx import Api, Resource, reqparse, Namespace, fields
import re
from sqlalchemy import func


app = Flask(__name__)


authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'name': 'Authorization',
        'in': 'header',
    }
}
api = Api(version=1.0, title='api문서', description='swagger 문서', doc='/api-docs', authorizations= authorizations, security='Bearer')

api.security = 'Bearer'

api.init_app(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234@localhost:3306/job_posting'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 회원 관련 api
auth = Namespace('auth', description='회원 관련 API')
api.add_namespace(auth)

# 공고 관련 api
jobs = Namespace('jobs', description='채용 공고 관련 API')
api.add_namespace(jobs)

# 지원 관련 api
application = Namespace('application', description='지원 관련 API')
api.add_namespace(application)



db = SQLAlchemy(app)

# 유저 모델
class User(db.Model):
    applications = db.relationship('Application', backref='user', lazy=True)


    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)

user_model = api.model('User', {
    'name': fields.String(required=True, description='사용자 이름'),
    'email': fields.String(required=True, description='사용자 이메일'),
    'password': fields.String(required=True, description='사용자 비밀번호')
})
loging_model = api.model('User',{
    'email': fields.String(required=True, description='사용자 이메일'),
    'password': fields.String(required=True, description='사용자 비밀번호')
})

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
    user = db.relationship('User', backref='bookmarks')
    posting = db.relationship('Posting', backref='bookmarks')

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
    posting = db.relationship('Posting', backref='applications')

    application_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=True)
    posting_id = db.Column(db.Integer, db.ForeignKey('posting.posting_id'), nullable=True)
    applied_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String, default='not applied')

apply_model = api.model('Apply', {
    'posting_id' : fields.String(required=True, description='장소')
})
# 토큰 설정
app.config.update(
        DEBUG=True,
        JWT_SECRET_KEY = "String"
)

jwt = JWTManager(app)

# email 확인
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None


# 회원관리
# 회원가입 처리
class UserRegister(Resource):
    @auth.doc(description='회원가입')
    @api.expect(user_model)
    def post(self):
        data = request.json

        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        hashed_password = generate_password_hash(password)

        if not name or not email or not password:
            return make_response(jsonify({"message": "이름, 이메일, 비밀번호를 모두 입력해 주세요."}), 400)


        # 이메일 형식 체크
        if not is_valid_email(email):
            return make_response(jsonify({"message" : "유효하지 않은 이메일 형식"}), 400)

        # 중복된 이메일 가입 처리
        chk = User.query.filter(User.email==email).first()
        if chk:
            return make_response(jsonify({"message" : "이미 가입된 이메일"}), 400)

        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return make_response(jsonify({"message": "회원 가입 완료"}), 201)

# 로그인
class UserLogin(Resource):
    @auth.doc(description='로그인')
    @api.expect(loging_model)
    def post(self):    
        data = request.json
        email = data.get('email')
        password = data.get('password')

        # 이메일 형식 체크
        if not is_valid_email(email):
            return make_response(jsonify({"message : 유효하지 않은 이메일 형식"}), 400)
        # 필수 데이터 체크
        if not email or not password:
            return make_response(jsonify({"message": "이메일, 비밀번호를 모두 입력해 주세요."}), 400)

        user = User.query.filter(User.email == email).first()
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=email)
            response = make_response(jsonify({"message" : "로그인 성공" , "access_token":access_token}), 200)
            response.headers["Authorization"] = f"Bearer {access_token}"

            return response

        return make_response(jsonify({"message": "로그인 실패: 잘못된 이메일 또는 비밀번호"}), 401)


# 사용자 정보 수정 이름, 비밀번호
# 회원 탈퇴
class UserUpdate(Resource):
    @jwt_required()
    @api.doc(description = '유저 정보 수정', security='Bearer')
    @api.expect(user_model)
    def put(self, email):
        user = User.query.filter(User.email == email).first()
        if user:
            data = request.json
            user.name = data.get('name', user.name)
            new_password = data.get('password')
            if new_password:
                hashed_password = generate_password_hash(new_password)
                user.password = hashed_password
            db.session.commit()
            return make_response(jsonify({"message": "회원 정보 수정 완료"}), 200)

        return make_response(jsonify({"message": "사용자를 찾을 수 없습니다."}), 404)

    @jwt_required()
    @api.doc(description = '유저 삭제', security='Bearer')
    def delete(self, email):
        user = User.query.filter(User.email == email).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return make_response(jsonify({"message": "회원 탈퇴 완료"}), 200)

        return make_response(jsonify({"message": "사용자를 찾을 수 없습니다."}), 404)

class TokenRefresh(Resource):
    @jwt_required()
    @api.doc(secription = '토큰 재발급', security='Bearer')
    def post(self, email):
            user = User.query.filter(User.email == email).first()
            access_token = create_access_token(identity=user.email)
        
            return make_response(jsonify({'access_token' : access_token}),200)


auth.add_resource(UserRegister, '/register', endpoint='user_register')
auth.add_resource(UserLogin, '/login', endpoint='user_login')
auth.add_resource(UserUpdate, '/users/<string:email>', endpoint='user_update')
auth.add_resource(TokenRefresh, '/refresh/<string:email>', endpoint='/refresh')


#지원하기 기능
#지원하기 (POST /applications)
class Apply(Resource):
    @application.doc(description ='지원하기')
    @jwt_required()
    @api.expect(apply_model)
    def post(self):
        # 현재 로그인한 사용자의 email을 통해 user_id를 가져옴
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()  
        if not user:
            return jsonify({"message": "사용자가 존재하지 않습니다."}), 404
        
        data = request.get_json()
        posting_id = data.get('posting_id')

        # posting_id가 유효한지 체크
        posting = Posting.query.filter_by(posting_id=posting_id).first()
        if not posting:
            return jsonify({"message": "존재하지 않는 채용 공고입니다."}), 400

        # 중복 지원 체크
        existing_application = Application.query.filter_by(user_id=user.user_id, posting_id=posting_id).first()
        if existing_application:
            return jsonify({"message": "이미 해당 공고에 지원하셨습니다."}), 400
        

        application = Application(user_id=user.user_id, posting_id=posting_id, status = 'applied')
        db.session.add(application)
        db.session.commit()

        return make_response(jsonify({"message": "지원이 완료되었습니다.", "application_id": application.application_id}), 201)

# 지원 내역 조회 (GET /applications)
class GetApply(Resource):
    @application.doc(description='지원 내역 조회')
    @api.param('user_id', '유저 아이디', _in='query', type='string', require=False )
    @api.param('posting_id', '공고 아이디', _in='query', type='string', require=False)
    @api.param('applied_at', '지원일', _in='query', type='Date', require=False)
    def get(self):
        # 쿼리 파라미터에서 user_id, posting_id, applied_at(날짜) 받기
        user_id = request.args.get('user_id', None)
        posting_id = request.args.get('posting_id', None)
        applied_at = request.args.get('applied_at', None)  # 날짜 필터링
        sort_order = request.args.get('sort', 'desc')  # 정렬 순서 (기본값: 내림차순)

        # 기본적으로 모든 지원 내역을 가져오는 쿼리
        query = Application.query

        # user_id가 있을 경우 해당 유저의 지원 내역 필터링
        if user_id:
            query = query.filter_by(user_id=user_id)

        # posting_id가 있을 경우 해당 게시물에 지원한 유저 이메일 조회
        if posting_id:
            query = query.filter_by(posting_id=posting_id)
            applications = query.all()
            result = [
                {
                    "user_email": app.user.email  # 이메일 조회
                }
                for app in applications
            ]
            return jsonify(result), 200

        # applied_at(날짜)이 있을 경우 해당 날짜에 지원한 내역 조회
        if applied_at:
            try:
                # 날짜 형식 변환 (ISO 형식으로 받았다고 가정)
                applied_at_date = datetime.datetime.strptime(applied_at, '%Y-%m-%d').date()
                query = query.filter(func.date(Application.applied_at) == applied_at_date)
            except ValueError:
                return jsonify({"message": "잘못된 날짜 형식입니다. 'YYYY-MM-DD' 형식으로 입력해 주세요."}), 400

        # 날짜별 정렬
        if sort_order == 'asc':
            query = query.order_by(Application.applied_at.asc())
        else:
            query = query.order_by(Application.applied_at.desc())

        # 쿼리 실행 후 결과 가져오기
        applications = query.all()

        # 결과를 JSON 형식으로 변환
        result = [
            {
                "application_id": app.application_id,
                "posting_id": app.posting_id,
                "status": app.status,
                "applied_at": app.applied_at.isoformat(),  
            }
            for app in applications
        ]

        # 결과 반환
        return make_response(jsonify(result), 200)


# 지원 취소from flask import jsonify, make_response
class DeleteApply(Resource):
    @jwt_required()
    @application.doc(description='지원 취소')
    @api.param('posting_id', '공고 아이디', _in='query', type='string', required=True)
    def delete(self):
        email = get_jwt_identity()

        user = User.query.filter_by(email=email).first()

        user_id = user.user_id

        # 요청에서 posting_id 가져오기
        posting_id = request.args.get('posting_id')
        
        # posting_id가 정수로 변환 가능한지 확인
        try:
            posting_id = int(posting_id)  # posting_id를 정수로 변환 (필요한 경우)
        except (ValueError, TypeError):
            return make_response(jsonify({"message": "잘못된 posting_id 형식입니다."}), 400)

        if not posting_id:
            return make_response(jsonify({"message": "취소할 posting_id를 입력하세요."}), 400)
    
        # user_id와 posting_id로 지원 내역 조회
        application = Application.query.filter_by(user_id=user_id, posting_id=posting_id).first()
        if not application:
            return make_response(jsonify({"message": "지원 내역을 찾을 수 없습니다."}), 404)

        # 지원 취소 가능 여부 확인
        if application.status != "applied":
            return make_response(jsonify({"message": "해당 지원은 취소할 수 없습니다."}), 400)

        # 상태 업데이트
        application.status = "cancelled"
        db.session.commit()

        # 응답을 JSON으로 반환 (직접 반환)
        return make_response(jsonify({"message": "지원이 취소되었습니다."}), 200)




application.add_resource(Apply, '/', endpoint='/application')
application.add_resource(GetApply, '/search', endpoint='/application/search')
application.add_resource(DeleteApply, '/delete', endpoint='/application/delete')


# 공고 

# 채용 공고 조회 (GET /jobs)
class ViewPost(Resource):
    @jobs.doc(description='채용 공고 조회')
    def get(self):
        postings = Posting.query.all()
        result = [
            {
                "company_name": posting.company.company_name,
                "title": posting.title,
                "career": posting.career,
                "education": posting.education,
                "deadline": posting.deadline,
                "skill": posting.skill
            }
            for posting in postings
        ]
        return make_response(jsonify(result), 200)

# 검색
class SearchPost(Resource):
    @api.doc(description='채용 공고 검색')
    @api.param('title', '채용 공고 제목', _in='query', type='string', required=False)
    @api.param('company_name', '회사 이름', _in='query', type='string', required=False)
    @api.param('career', '경력', _in='query', type='string', required=False)
    @api.param('education', '학력', _in='query', type='string', required=False)
    @api.param('skill', '요구 기술', _in='query', type='string', required=False)
    def get(self):
        
        title = request.args.get('title', None)  
        company_name = request.args.get('company_name', None)  
        career = request.args.get('career', None)  
        education = request.args.get('education', None)  
        skill = request.args.get('skill', None)  

        
        query = Posting.query
        
        if title:
            query = query.filter(Posting.title.ilike(f'%{title}%'))
        if company_name:
            query = query.join(Company).filter(Company.company_name.ilike(f'%{company_name}%'))
        if career:
            query = query.filter(Posting.career.ilike(f'%{career}%'))
        if education:
            query = query.filter(Posting.education.ilike(f'%{education}%'))
        if skill:
            query = query.filter(Posting.skill.ilike(f'%{skill}%'))
        
        postings = query.all()
        
        # 결과 반환
        result = [
            {
                "posting_id": posting.posting_id,
                "company_id": posting.company_id,
                "company_name": posting.company.company_name,
                "title": posting.title,
                "career": posting.career,
                "education": posting.education,
                "deadline": posting.deadline,
                "skill": posting.skill
            }
            for posting in postings
        ]
        
        return make_response(jsonify(result),200)

# 필터링
class FilterPost(Resource):
    @api.doc(description='채용 공고 검색')
    @api.param('place', '장소', _in='query', type='string', required=False)
    def get(self):
        place = request.args.get('place', None)  

        query = Posting.query

        if place: 
            query = query.join(Company).filter(Company.company_place.ilike(f'%{place}%'))

        postings = query.all()

        result = [
            {
                "posting_id": posting.posting_id,
                "company_id": posting.company_id,
                "company_name": posting.company.company_name,
                "title": posting.title,
                "career": posting.career,
                "education": posting.education,
                "deadline": posting.deadline,
                "skill": posting.skill,
                "company_place": posting.company.company_place
            }
            for posting in postings
        ]
        
        return make_response(jsonify(result), 200)



jobs.add_resource(FilterPost, '/filter', endpoint='/filter')
jobs.add_resource(SearchPost, '/search')
jobs.add_resource(ViewPost, '/', endpoint='/view')



if __name__ == '__main__':
    app.run(debug=True)