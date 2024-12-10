-- MySQL dump 10.13  Distrib 8.0.36, for Win64 (x86_64)
--
-- Host: localhost    Database: job_posting
-- ------------------------------------------------------
-- Server version	8.0.37

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `company`
--

DROP TABLE IF EXISTS `company`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `company` (
  `company_id` int NOT NULL AUTO_INCREMENT,
  `company_name` varchar(255) NOT NULL,
  `company_category` varchar(255) NOT NULL,
  `company_url` varchar(255) NOT NULL,
  `company_place` varchar(255) NOT NULL,
  PRIMARY KEY (`company_id`),
  UNIQUE KEY `company_name` (`company_name`)
) ENGINE=InnoDB AUTO_INCREMENT=114 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `company`
--

LOCK TABLES `company` WRITE;
/*!40000 ALTER TABLE `company` DISABLE KEYS */;
INSERT INTO `company` VALUES (1,'(주)소만사','No category','http://www.somansa.com','서울 영등포구 영신로 220'),(2,'피씨엔오티(주)','반도체 제조용 기계 제조업','http://www.pcnot.net','경기 화성시 떡전골로 96-4, 702호 (병점동,미라클프라자)'),(3,'(주)테크웨이즈','http://www.techways.co.kr','https://www.youtube.com/watch?v=rvAdUr1V9yM','No address'),(4,'루펜티스(주)','주거용 건물 개발 및 공급업','No homepage URL','No address'),(5,'에이에이씨티(유)','기타 보관 및 창고업','http://service.aact.co.kr/','인천 중구 공항동로295번길 60 (운서동,에이에이씨티 제2화물터미널)'),(6,'(주)콤텍시스템','컴퓨터 프로그래밍 서비스업','http://www.comtec.co.kr','서울 영등포구 가마산로 343'),(7,'아우토크립트(주)','응용 소프트웨어 개발 및 공급업','http://autocrypt.co.kr','서울 영등포구 여의공원로 115, 지하 1층, 1층, 6층, 7층, 8층 (여의도동,세우빌딩)'),(8,'(주)에스티에이테스팅컨설팅','응용 소프트웨어 개발 및 공급업','http://www.sta.co.kr','서울 광진구 자양강변길 115'),(9,'비와이아이엔씨(주)','응용 소프트웨어 개발 및 공급업','http://www.tncation.com','서울 송파구 법원로 128, B동 7층 710호'),(10,'(주)피코이노베이션','그 외 기타 분류 안된 운송 관련 서비스업','https://picoinnov.com/','서울 서초구 효령로36길 4, 2층 (방배동,제약조합)'),(11,'삼양데이타시스템(주)','컴퓨터시스템 통합 자문 및 구축 서비스업','http://www.syds.com','서울 종로구 종로33길 31'),(12,'(주)케이엠헬스케어','의료용품 도매업','http://www.kmhealthcare.co.kr','경기 구리시 동구릉로395번길 144'),(13,'넷킬러(주)','컴퓨터 프로그래밍 서비스업','http://www.netkiller.com','서울 강남구 영동대로 417, 지하1층 (대치동,오토웨이타워)'),(14,'(주)인티그리트','산업용 로봇 제조업','http://integrit.ai','서울 강남구 삼성로 547, 5층 (삼성동,비케이타워)'),(15,'하이엠케이(주)','알루미늄 압연, 압출 및 연신제품 제조업','No homepage URL','No address'),(16,'(주)폴리인스퍼레이션','서적, 잡지 및 기타 인쇄물 도매업','https://www.polyinspiration.com/','서울 송파구 송파대로 201, B동 4층 (문정동,송파테라타워2)'),(17,'(주)케이엘넷','그 외 기타 전기 통신업','http://www.klnet.co.kr','서울 강남구 역삼로 153'),(18,'(주)에코이앤이','지정 외 폐기물 처리업','No homepage URL','No address'),(19,'(주)사조시스템즈','비주거용 건물 임대업','http://www.sajosys.com','서울 서대문구 통일로 107-39'),(20,'(주)천재교육','교과서 및 학습서적 출판업','http://www.chunjae.co.kr','서울 금천구 가산로9길 54'),(21,'(주)디알젬','방사선 장치 제조업','http://www.drgem.co.kr','경기 광명시 하안로 60, E동 7층 (소하동,광명테크노파크)'),(22,'메이저월드(주)','운동 및 경기용품 도매업','http://www.mwd.kr','경기 화성시 동탄기흥로 557, 14층 1407, 1408호 (영천동,동탄금강펜테리움아이티타워)'),(23,'마키타엔지니어링코리아(주)','기타 엔지니어링 서비스업','http://www.makita.biz/','서울 강남구 테헤란로 401, 12층 (삼성동,남경센터빌딩)'),(24,'주식회사 핌아시아','전자상거래 소매 중개업','http://fimasia.recruiter.co.kr','서울 강남구 테헤란로114길 16, 3층 (대치동,동남빌딩)'),(25,'부산대학교지능물류빅데이터연구소','기타 인문 및 사회과학 연구개발업','No homepage URL','No address'),(26,'(주)신한은행','국내은행','http://www.shinhan.com','서울 중구 세종대로9길 20'),(27,'한국영상대학교','일반 교과 학원','http://www.pro.ac.kr','세종 장군면 대학길 300'),(28,'(주)데이터쿡','컴퓨터 프로그래밍 서비스업','http://www.datacook.kr','서울 마포구 월드컵로8길 45-8, 3층 3073호 (서교동,양성빌딩)'),(29,'유니닥스(주)','응용 소프트웨어 개발 및 공급업','http://www.unidocs.co.kr','No address'),(30,'(주)글로벌스탠다드테크놀로지','반도체 제조용 기계 제조업','http://www.gst-in.com','경기 화성시 동탄산단6길 15-13'),(31,'(주)벨아이앤에스','컴퓨터시스템 통합 자문 및 구축 서비스업','http://www.bellins.net ','서울 서대문구 충정로 8 (충정로3가,종근당빌딩)'),(32,'한국전광(주)','광학렌즈 및 광학요소 제조업','http://www.keoc.kr','인천 계양구 서운산단로2길 36'),(33,'(주)엔비솔루션','사진기, 영사기 및 관련 장비 제조업','https://www.envysolution.com/','경기 안양시 동안구 흥안대로439번길 8, 4층'),(34,'한국장애인고용공단','그 외 기타 비거주 복지 서비스업','http://www.kepad.or.kr','경기 성남시 분당구 구미로173번길 59'),(35,'대성공업(주)','그 외 자동차용 신품 부품 제조업','http://www.dsi21.co.kr','등산동호회, 축구동호회, 볼링동호회, 스노보드동호회'),(36,'(주)아남아이티','컴퓨터 및 주변장치, 소프트웨어 도매업','http://www.anaminfo.com','대구 수성구 알파시티1로42길 11, 923호,924호 (대흥동,태왕알파시티수성)'),(37,'(주)동일캔바스엔지니어링','그 외 기타 분류 안된 섬유제품 제조업','http://www.canvaskorea.com','경기 평택시 서탄면 내천길 105-10'),(38,'시큐레터(주)','http://www.seculetter.com','No hompage URL','No address'),(39,'(주)에이젝코리아','사업시설 유지ㆍ관리 서비스업','http://www.agekke.co.kr','서울 중구 소월로 10, 9층'),(40,'(주)세스코','소독, 구충 및 방제 서비스업','http://www.cesco.co.kr','No address'),(41,'(주)웰데이타시스템','시스템 소프트웨어 개발 및 공급업','http://www.ncloud24.com','경기 성남시 분당구 대왕판교로644번길 86, 4층 (삼평동,케이티동판교빌딩)'),(42,'(주)맨파워그룹코리아','상용 인력 공급 및 인사관리 서비스업','http://manpower.co.kr','서울 강남구 테헤란로 409'),(43,'주식회사드림캐쳐스','광고·홍보·전시','http://map.kakao.com/link/map/%EC%A3%BC%EC%8B%9D%ED%9A%8C%EC%82%AC%EB%93%9C%EB%A6%BC%EC%BA%90%EC%B3%90%EC%8A%A4,37.6558964094856,126.772038816453','No address'),(44,'(주)제이비케이랩','건강기능식품 제조업','http://www.jbklab.co.kr/','경기 성남시 중원구 둔촌대로 464, 2층'),(45,'셀렉트스타(주)','데이터베이스 및 온라인정보 제공업','http://www.selectstar.ai','대전 서구 대덕대로233번길 28, 601호'),(46,'베스핀글로벌(주)','컴퓨터시스템 통합 자문 및 구축 서비스업','https://www.bespinglobal.com/','서울 서초구 강남대로 327, 13층,14층,15층,16층 (서초동,대륭서초타워)'),(47,'주식회사로아','솔루션·SI·ERP·CRM','http://map.kakao.com/link/map/%EC%A3%BC%EC%8B%9D%ED%9A%8C%EC%82%AC%EB%A1%9C%EC%95%84,35.1443184545334,129.036309884005','No address'),(48,'(주)비엔케이시스템','컴퓨터시스템 통합 자문 및 구축 서비스업','http://bnksys.co.kr','부산 강서구 미음산단로127번길 21'),(49,'티디케이한국(주)','전자축전기 제조업','http://www.kr.tdk.com','경기 평택시 청북읍 현곡산단로 104'),(50,'쿠어스텍코리아(유)','위생용 및 산업용 도자기 제조업','http://www.coorstek.com','경북 구미시 4공단로7길 23-28'),(51,'(주)에스제이그룹','가방 및 기타 보호용 케이스 제조업','http://www.kangolkorea.com','서울 강남구 도곡로 156'),(52,'(주)소프트위드솔루션','http://www.softwith.com','No hompage URL','No address'),(53,'(주)대륜','컴퓨터시스템 통합 자문 및 구축 서비스업','https://www.daeryunlaw.com','서울 영등포구 여의대로 24, 21층'),(54,'(주)하이텔레서비스','콜센터 및 텔레마케팅 서비스업','http://www.hiteleservice.co.kr','서울 강서구 마곡중앙5로 18, 3,4,5층'),(55,'(주)피아이이','그 외 기타 특수목적용 기계 제조업','http://www.piegroup.co.kr/','경기 화성시 동탄기흥로 614, 19층 (영천동,더퍼스트타워2차)'),(56,'(주)위포','컴퓨터 및 주변장치, 소프트웨어 도매업','http://www.wefor.com','대전 서구 둔산대로117번길 102'),(57,'(주)마텍무역','의료기기 도매업','http://www.marktech.co.kr','경기 안양시 만안구 예술공원로154번길 7, 2층 (안양동,마텍빌딩)'),(58,'중앙일보(주)','신문 발행업','No homepage URL','No address'),(59,'한국로슈진단(주)','의약품 도매업','http://www.roche-diagnostics.co.kr','서울 강남구 테헤란로108길 22'),(60,'에이치제이네트웍스','솔루션·SI·ERP·CRM','http://map.kakao.com/link/map/%EC%97%90%EC%9D%B4%EC%B9%98%EC%A0%9C%EC%9D%B4%EB%84%A4%ED%8A%B8%EC%9B%8D%EC%8A%A4,37.4766451549316,126.889578522942','No address'),(61,'이제너두(주)','데이터베이스 및 온라인정보 제공업','http://www.etbs.co.kr','서울 강남구 강남대로 556, 16층 (논현동,이투데이빌딩)'),(62,'(주)에너토크','탭, 밸브 및 유사장치 제조업','http://www.enertork.com','경기 여주시 세종대왕면 능여로 344'),(63,'(주)유엔에이엔지니어링','통신장비 수리업','https://www.unaengineering.com/kr/','경기 군포시 공단로 149, 701호 (당동,군포아이밸리)'),(64,'(주)드림하이테크','컴퓨터 프로그래밍 서비스업','http://drimhitech.com ','경기 수원시 영통구 덕영대로1556번길 16, E동 801호'),(65,'씨제이포디플렉스(주)','기타 공학 연구개발업','http://www.cj4dx.com','서울 용산구 한강대로23길 55, 8층 (한강로3가,아이파크몰)'),(66,'코스텍시스템(주)','반도체 제조용 기계 제조업','http://www.kosteks.com','경기 평택시 서탄면 방꼬지길 231'),(67,'주식회사 대륜','컴퓨터시스템 통합 자문 및 구축 서비스업','https://www.daeryunlaw.com','서울 영등포구 여의대로 24, 21층'),(68,'(주)엠쓰리모바일','기타 무선 통신장비 제조업','http://www.m3mobile.co.kr','서울 금천구 가산디지털1로 196, 1107~1109호 (가산동,에이스테크노타워10차)'),(69,'(주)티엑스알로보틱스','컨베이어장치 제조업','http://www.gubunki.com','경기 부천시 원미구 옥산로 216'),(70,'한국이콜랩(유)','그 외 기타 분류 안된 화학제품 제조업','http://www.Ecolab.com','서울 송파구 법원로 135, 8층 (문정동,소노타워)'),(71,'한화호텔앤드리조트(주)','휴양콘도 운영업','https://www.hwrc.co.kr/hwrc/index.do','No address'),(72,'(주)인피닉','응용 소프트웨어 개발 및 공급업','http://www.infiniq.co.kr','서울 금천구 가산디지털1로 186, 701호 (가산동,제이플라츠)'),(73,'(주)제이에스티','디스플레이 제조용 기계 제조업','http://www.jst-tech.co.kr','충남 아산시 배방읍 고속철대로 43, 1동 201호'),(74,'(주)지아이티','물질 검사, 측정 및 분석기구 제조업','http://www.gitauto.com','서울 송파구 마천로 87'),(75,'신성통상(주)','직물 도매업','http://www.ssts.co.kr','서울 강동구 풍성로63길 84'),(76,'(주)칼리버스','응용 소프트웨어 개발 및 공급업','http://www.caliverse.co.kr','서울 강남구 선릉로146길 27-7'),(77,'(주)글로벌모터서비스','그 외 기타 분류 안된 전문, 과학 및 기술 서비스업','http://www.globalmotorservice.co.kr/','서울 강남구 테헤란로 447, 14층'),(78,'(주)인지이솔루션','축전지 제조업','http://www.inzi-esol.co.kr','대전 유성구 테크노2로 80-28'),(79,'(주)래딕스','측정, 시험, 항해, 제어 및 기타 정밀기기 제조업','http://www.radixfa.com','대구 달서구 호산로 89'),(80,'(주)리더마인','응용 소프트웨어 개발 및 공급업','http://www.leadermine.co.kr','서울 강남구 논현로99길 23, 비1-1호 (역삼동,인사이트빌딩)'),(81,'(주)건담앤컴퍼니','컴퓨터시스템 통합 자문 및 구축 서비스업','http://www.gdnc.co.kr','서울 송파구 백제고분로 446, 3층 (방이동,송암빌딩)'),(82,'데상트코리아(주)','남녀용 겉옷 및 셔츠 도매업','http://www.descentekorea.co.kr','서울 송파구 올림픽로 300, 32층 (신천동,롯데월드타워)'),(83,'동아화성(주)','고무패킹류 제조업','http://www.dacm.com','경남 김해시 유하로 154-9'),(84,'(주)유아이에스','컴퓨터 및 주변장치, 소프트웨어 도매업','http://www.uistech.co.kr','No address'),(85,'동성인재개발교육원','기타 기술 및 직업훈련학원','http://www.dshrd.or.kr','부산 부산진구 중앙대로 668, 6층 (부전동,에이원프라자)'),(86,'(주)드림텍','그 외 기타 전자부품 제조업','http://www.idreamtech.co.kr','경기 성남시 분당구 대왕판교로 670, 에이동 10층 1001호, 1004호, 1005호 (삼평동,판교테크노밸리 유스페이스2)'),(87,'(주)에이블리','전기·전자·제어','No homepage URL','No address'),(88,'신일제약(주)','완제 의약품 제조업','http://www.sinilpharm.com','충북 충주시 앙성면 복상골길 28'),(89,'(주)네오랩컨버전스','이상규','http://map.kakao.com/link/map/%EC%A3%BC%EC%8B%9D%ED%9A%8C%EC%82%AC+%EB%84%A4%EC%98%A4%EB%9E%A9%EC%BB%A8%EB%B2%84%EC%A0%84%EC%8A%A4,37.4821079378772,126.895281502292','No address'),(90,'(주)지란지교시큐리티','응용 소프트웨어 개발 및 공급업','https://jiransecurity.com','경기 성남시 수정구 금토로80번길 37, 4층 (금토동,인피니티타워)'),(91,'(주)가스트론','전기경보 및 신호장치 제조업','http://www.gastron.com','경기 군포시 군포첨단산업1로 23'),(92,'(주)비투엔','응용 소프트웨어 개발 및 공급업','http://www.b2en.com','서울 용산구 서빙고로51길 52, 2층'),(93,'네이버시스템(주)','응용 소프트웨어 개발 및 공급업','http://www.neighbor21.co.kr','서울 송파구 중대로 135, 동관 16층 1601호 (가락동,아이티벤처타워)'),(94,'(주)에이치제이','표면처리 및 적층 직물 제조업','http://www.hjlite.com','경기 화성시 향남읍 발안공단로4길 30'),(95,'(주)비아이지엠','기타 가공식품 도매업','http://map.kakao.com/link/map/%28%EC%A3%BC%29%EB%B9%84%EC%95%84%EC%9D%B4%EC%A7%80%EC%97%A0,37.6625507246319,127.040568535069','No address'),(96,'(주)크레이버코퍼레이션','화장품 및 화장용품 도매업','https://www.cravercorp.com/','서울 강남구 테헤란로4길 14, 12층 (역삼동,미림타워)'),(97,'(주)메디코슨','http://www.medicoson.com','No hompage URL','No address'),(98,'쿠팡풀필먼트서비스(유)','기타 육상 운송지원 서비스업','No homepage URL','No address'),(99,'(주)에이치알에스','합성수지 및 기타 플라스틱 물질 제조업','http://www.hrssilicone.com','경기 평택시 팽성읍 추팔산단2길 7'),(100,'나이스피앤아이(주)','데이터베이스 및 온라인정보 제공업','http://www.nicepricing.co.kr','서울 영등포구 국회대로70길 19, 4층'),(101,'주식회사 스포츠시그널','포털·인터넷·컨텐츠','http://map.kakao.com/link/map/%EC%A3%BC%EC%8B%9D%ED%9A%8C%EC%82%AC+%EC%8A%A4%ED%8F%AC%EC%B8%A0%EC%8B%9C%EA%B7%B8%EB%84%90,37.4928727432965,127.012979871645','No address'),(102,'(주)이티에스','그 외 기타 특수목적용 기계 제조업','http://www.ets1.co.kr','충남 아산시 음봉면 스마트산단로 91'),(103,'(주)코디','화장품 제조업','http://www.kodi.co.kr','경기 용인시 수지구 광교중앙로 338, 에이동 에이301호, 에이302호, 에이303호,에이304호,에이308호, 에이309호, 에이310호,에이315호, 에'),(104,'뉴클(주)','교육관련 자문 및 평가업','http://www.newkl.net','서울 송파구 송파대로 201, B동 1707호 (문정동,송파테라타워2)'),(105,'(주)지에스티','응용 소프트웨어 개발 및 공급업','http://www.gsti.co.kr','부산 북구 효열로 111, 302호 (금곡동,부산지식산업센터)'),(106,'(주)나라스페이스테크놀로지','기타 공학 연구개발업','http://www.naraspace.com','No address'),(107,'(주)하이브랩','응용 소프트웨어 개발 및 공급업','http://www.hivelab.co.kr','경기 성남시 분당구 대왕판교로 670, A동 8층 (삼평동,유스페이스2)'),(108,'(재)만불회','협회·단체','http://www.manbulsa.org','경북 영천시 북안면 고지리 산46번지 만불사'),(109,'(주)일신비츠온','전지 및 케이블 도매업','http://vitson.co.kr','경기 남양주시 진접읍 팔야산단로12번길 55, 56'),(110,'(주)두원전자통신','방송장비 제조업','http://www.doowoninc.com','경기 부천시 오정구 석천로 397, 301동 408호 (삼정동,부천테크노파크3차)'),(111,'한양이엔지(주)','건축설계 및 관련 서비스업','http://www.hanyangeng.co.kr','경기 화성시 영통로26번길 72'),(112,'윈덤그랜드부산','호텔·여행·항공','https://www.wyndhamgrandbusan.com/kor/','No address'),(113,'센소파트코리아(주)','그 외 기타 분류 안된 사업지원 서비스업','http://www.sensopart.com/ko','경기 화성시 동탄첨단산업1로 27, B동 2층 35호, 36호 (영천동,금강펜테리움아이엑스타워)');
/*!40000 ALTER TABLE `company` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-12-10 23:23:45
