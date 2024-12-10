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

# 북마크 관련 api
bookmark = Namespace('bookmark', description='북마크 관련 API')
api.add_namespace(bookmark)

# 이력서 관련 api
resume = Namespace('resume', description='이력서 관련 API')
api.add_namespace(resume)

# 리뷰 관련 api
review = Namespace('review', description='리뷰 관련 API')
api.add_namespace(review)

# 대기업 정보 api
curation = Namespace('curation', description='대기업 관련 API')
api.add_namespace(curation)

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
bookmark_model = api.model('Bookmark',{
    'posting_id' : fields.String(required=True, description='포스팅아이디')
})

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

# 이력서 모델
class Resume(db.Model):
    user = db.relationship('User', backref='resume')

    resume_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    resume_content = db.Column(db.String)

resume_model = api.model('Resume', {
    'content' : fields.String(required=True, description='내용')
})
# 리뷰 모델
class Review(db.Model):
    user = db.relationship('User', backref='review')
    posting = db.relationship('Posting', backref='review')

    review_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    posting_id = db.Column(db.Integer, db.ForeignKey('posting.posting_id'), nullable=False)
    review_content = db.Column(db.String)
review_model = api.model('Review', {
    'company_id' : fields.String(required=True, description='회사 아이디'),
    'review_content' : fields.String(required=True, description='리뷰')
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
    @api.param('page', '페이지 번호 (기본값: 1)', type=int, default=1)
    @api.param('per_page', '페이지 당 항목 수 (기본값: 20)', type=int, default=20)
    @api.param('sort_by', '정렬 기준 필드 (기본값: deadline)', type=str, default='deadline')
    @api.param('sort_order', '정렬 순서 (asc 또는 desc, 기본값: asc)', type=str, default='asc')
    def get(self):
        # 페이지네이션을 위한 파라미터 받기
        page = request.args.get('page', 1, type=int)  
        per_page = request.args.get('per_page', 20, type=int)  
        sort_by = request.args.get('sort_by', 'deadline', type=str)  
        sort_order = request.args.get('sort_order', 'asc', type=str)  

        # 정렬 방향 설정 (asc 또는 desc)
        if sort_order == 'asc':
            order_by = getattr(Posting, sort_by).asc()
        elif sort_order == 'desc':
            order_by = getattr(Posting, sort_by).desc()
        else:
            return make_response(jsonify({"message": "Invalid sort_order"}), 400)

        # 페이지네이션 및 정렬
        postings = Posting.query.order_by(order_by).paginate(page=page, per_page=per_page, error_out=False)

        # 결과가 없으면 404 반환
        if not postings.items:
            return make_response(jsonify({"message": "No postings found"}), 404)

        result = [
            {
                "company_name": posting.company.company_name,
                "title": posting.title,
                "career": posting.career,
                "education": posting.education,
                "deadline": posting.deadline,
                "skill": posting.skill
            }
            for posting in postings.items
        ]

        return make_response(jsonify({
            "postings": result,
            "total": postings.total,
            "pages": postings.pages,
            "current_page": postings.page
        }), 200)
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

# 북마크

# 북마크 추가 삭제
class BookmarkResource(Resource):
    @jwt_required()
    @api.expect(bookmark_model)
    def post(self):
        email = get_jwt_identity()

        user = User.query.filter_by(email=email).first()

        user_id = user.user_id


        # 요청에서 posting_id 가져오기
        posting_id = request.json.get('posting_id')

        if not posting_id:
            return make_response(jsonify({"message": "posting_id가 필요합니다."}), 400)

        # 이미 북마크가 존재하는지 확인
        existing_bookmark = Bookmark.query.filter_by(user_id=user_id, posting_id=posting_id).first()

        if existing_bookmark:
            # 북마크가 이미 존재하면 삭제
            db.session.delete(existing_bookmark)
            db.session.commit()
            return make_response(jsonify({"message": "북마크가 제거되었습니다."}), 200)
        else:
            # 북마크가 존재하지 않으면 추가
            new_bookmark = Bookmark(user_id=user_id, posting_id=posting_id)
            db.session.add(new_bookmark)
            db.session.commit()
            return make_response(jsonify({"message": "북마크가 추가되었습니다."}), 201)

# 북마크 목록 조회
class BookmarkListResource(Resource):
    @api.param('user_id', '유저의 ID', _in='query', type='integer', required=True)
    def get(self):
        user_id = request.args.get('user_id')  # 쿼리 파라미터로 user_id 받기

        if not user_id:
            return jsonify({"message": "user_id가 필요합니다."}), 400

        # 페이지네이션을 위한 기본값
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # user_id로 해당하는 북마크 목록 조회
        bookmarks_query = Bookmark.query.filter_by(user_id=user_id)

        # 페이지네이션 적용
        bookmarks = bookmarks_query.paginate(page=page, per_page=per_page, error_out=False)

        # 결과가 없으면 404 반환
        if not bookmarks.items:
            return make_response(jsonify({"message": "북마크가 없습니다."}), 404)

        # 북마크 목록을 리스트로 변환하여 반환
        result = [{"bookmark_id": bookmark.bookmark_id, "posting_id": bookmark.posting_id} for bookmark in bookmarks.items]
        
        return make_response(jsonify({
            "bookmarks": result,
            "total": bookmarks.total,
            "pages": bookmarks.pages,
            "current_page": bookmarks.page
        }), 200)


bookmark.add_resource(BookmarkResource, '/bookmarks')
bookmark.add_resource(BookmarkListResource, '/bookmarks/search')


# 이력서

# 이력서 추가
class AddResume(Resource):
    @api.expect(resume_model)
    @jwt_required() 
    def post(self):
        
        user_email = get_jwt_identity()

        user = User.query.filter_by(email=user_email).first()
        if not user:
            return make_response(jsonify({"msg": "User not found"}), 404)

        # 요청 본문에서 이력서 내용 받기
        resume_content = request.json.get('resume_content')

        # 이력서 추가
        resume = Resume(user_id=user.user_id, resume_content=resume_content)
        db.session.add(resume)
        db.session.commit()

        return make_response(jsonify({"msg": "Resume added successfully", "resume_id": resume.resume_id}), 201)

# 이력서 조회
class GetResume(Resource):
    @api.param('user_id', '검색할 유저 아이디', type=int, required=True)
    def get(self):
        # 쿼리 파라미터로 받은 user_id 가져오기
        user_id = request.args.get('user_id', type=int)

        # 유저 ID가 없는 경우 처리
        if not user_id:
            return make_response(jsonify({"msg": "User ID is required"}), 400)

        # 해당 유저의 이력서 조회
        resume = Resume.query.filter_by(user_id=user_id).first()

        # 이력서가 없는 경우 처리
        if not resume:
            return make_response(jsonify({"msg": "Resume not found"}), 404)

        # 이력서 정보 반환
        return make_response(jsonify({
            "resume_id": resume.resume_id,
            "resume_content": resume.resume_content
        }), 200)
    

# 이력서 삭제
class DeleteResume(Resource):
    @jwt_required()
    @api.param('resume_id', '삭제할 이력서 번호', type=int, required=True)  
    def delete(self):
        
        user_email = get_jwt_identity()

        # 사용자 정보 조회
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return make_response(jsonify({"msg": "User not found"}), 404)

        # 이력서 번호 파라미터 조회
        resume_id = request.args.get('resume_id', type=int)
        if not resume_id:
            return make_response(jsonify({"msg": "Resume ID is required"}), 400)

        # 해당 이력서 조회
        resume = Resume.query.filter_by(resume_id=resume_id, user_id=user.user_id).first()
        if not resume:
            return make_response(jsonify({"msg": "Resume not found"}), 404)

        # 이력서 삭제
        db.session.delete(resume)
        db.session.commit()

        return make_response(jsonify({"msg": "Resume deleted successfully"}), 200)
    
resume.add_resource(AddResume, '/add')
resume.add_resource(GetResume, '/get')
resume.add_resource(DeleteResume, '/delete')



# 대기업 조회
class SearchCompany(Resource):
    @api.param('curation_company_name', '조회할 회사명 (일부 텍스트 가능)', type=str, required=True)
    def get(self):
        # 회사명 가져오기
        company_name = request.args.get('curation_company_name')

        if not company_name:
            return make_response(jsonify({"msg": "Company name is required"}), 400)

        # 회사명으로 데이터를 검색
        companies = Top.query.filter(Top.curation_company_name.like(f"%{company_name}%")).all()

        if not companies:
            return make_response(jsonify({"msg": "No matching companies found"}), 404)

        result = [
            {
                "curation_company_id": company.curation_company_id,
                "curation_company_name": company.curation_company_name,
                "curation_company_type": company.curation_company_type,
                "curation_company_year": company.curation_company_year,
                "curation_company_genre": company.curation_company_genre,
            }
            for company in companies
        ]

        return make_response(jsonify(result), 200)

curation.add_resource(SearchCompany, '/curationcompany')


# 리뷰

#리뷰 조회
class GetReviews(Resource):
    @api.param('company_id', 'Company ID to fetch reviews', type=int, required=True)
    def get(self):

        company_id = request.args.get('company_id', type=int)
        # 해당 회사의 리뷰 조회
        reviews = Review.query.join(Posting, Review.posting_id == Posting.posting_id) \
                              .filter(Posting.company_id == company_id).all()
        if not reviews:
            return make_response(jsonify({"msg": "No reviews found for this company"}), 404)

        # 리뷰 목록 반환
        result = [
            {
                "review_id": review.review_id,
                "user_id": review.user_id,
                "review_content": review.review_content
            }
            for review in reviews
        ]
        return make_response(jsonify(result), 200)

# 리뷰 등록
class AddReview(Resource):
    @jwt_required()
    @api.expect(review_model)
    def post(self):
        data = request.get_json()
        company_id = data.get('company_id')
        review_content = data.get('review_content')

        if not company_id or not review_content:
            return make_response(jsonify({"msg": "Company ID and review content are required"}), 400)

        # 현재 로그인한 사용자 정보 조회
        user_email = get_jwt_identity()
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return make_response(jsonify({"msg": "User not found"}), 404)

        # 회사 존재 여부 확인
        posting = Posting.query.filter_by(company_id=company_id).first()
        if not posting:
            return make_response(jsonify({"msg": "Company not found"}), 404)

        # 리뷰 생성
        new_review = Review(
            user_id=user.user_id,
            posting_id=posting.posting_id,
            review_content=review_content
        )
        db.session.add(new_review)
        db.session.commit()

        return make_response(jsonify({"msg": "Review added successfully"}), 201)

review.add_resource(GetReviews, '/getreview')
review.add_resource(AddReview, '/addreview')

if __name__ == '__main__':
    app.run(debug=True)