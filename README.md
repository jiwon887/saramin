## 주요 기능

### 네임스페이스
- **`auth`**: 회원 관련 API
- **`jobs`**: 채용 공고 관련 API
- **`application`**: 지원 관련 API
- **`bookmark`**: 북마크 관련 API
- **`resume`**: 이력서 관련 API
- **`review`**: 리뷰 관련 API
- **`curation`**: 대기업 관련 API

---

## 요구사항

- Python 3.8 이상
- Flask 2.0 이상
- Flask-RESTX 0.5.2 이상

---

## 설치 및 실행

### 1. 가상환경 생성 및 활성화
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 2. 의존성 설치
```bash
pip install -r requirements.txt
```

### 3. 애플리케이션 실행
```bash
python app.py
```
## 네임스페이스 설명

### `auth` (회원 관련 API)
- 회원가입, 로그인 등 사용자 계정 관리 기능 제공
- email을 아이디로 사용
  
## /auth/login  - 로그인 기능
* email = 이메일 입력
* password = 비밀번호 입력

## /auth/refresh/{email} - 토큰 재발급
* email = 이메일 입력
* password = 비밀번호 입력

## /auth/register - 회원가입
* email = 이메일 입력
* password = 비밀번호 입력 

## /auth/users/{email} - 회원탈퇴
* email = 이메일 입력

## /auth/users/{email} - 회원 정보 수정
* email = 이메일 입력
* password = 비밀번호 입력

### `jobs` (채용 공고 관련 API)
- 채용 공고 검색 및 조회 관련 기능 제공

## /jobs/ - 채용 공고 조회
* sort_orer = desc(내림차순), asc(오름차순)
* sort_by = string(마감일)
* per_page = int(페이지에 띄울 공고 수)
* page = int(페이지 번호)

## /jobs/filter - 채용 공고 필터링
* place = place(지명 입력)

## /jobs/search - 채용 공고 검색
* skill = string(요구 기술)
* education = string(학력)
* career = string(경력)
* comapany_name = string(회사명)
* title = string(제목)
  
### `application` (지원 관련 API)
- 채용 공고에 지원하는 기능 제공



### `bookmark` (북마크 관련 API)
- 채용 공고 북마크 관리 기능 제공

### `resume` (이력서 관련 API)
- 사용자 이력서 작성 및 조회 기능 제공

### `review` (리뷰 관련 API)
- 회사 리뷰 작성 및 조회 기능 제공

### `curation` (대기업 관련 API)
- 대기업 정보 제공 기능 제공

---

## 참고
- Flask-RESTX를 사용하여 API 문서화와 테스트 기능을 제공합니다.
- 자세한 API 사용 방법은 Swagger UI를 통해 확인하세요.
