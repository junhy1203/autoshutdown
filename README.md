# SmartPower — Windows PC 원격 전원 관리

여러 Windows PC의 상태를 한 화면에서 확인하고 종료·재시작·예약 작업을 관리하는 **데스크톱 에이전트 + 웹 대시보드** 프로젝트입니다. PC 프로그램, 자체 서버, Firebase 연동 코드와 설치·업데이트 도구를 함께 제공합니다.

![SmartPower 대시보드](dashboard-desktop.png)

## 주요 기능

- **장치 모니터링:** PC 이름·사용자·IP 검색, 온라인/오프라인 필터, 정렬 및 통합 현황
- **원격 전원 제어:** 개별·일괄 종료/재시작 명령과 실수 방지를 위한 슬라이드 확인
- **예약 및 자동화:** PC별 일정 설정, 자정을 넘기는 예약 처리, 실행 프로그램 관리
- **실시간 상태:** Firebase 기반 상태 동기화와 자체 서버 연결, 연결 지연 시 대체 조회
- **화면 확인:** 지원 에이전트의 클라우드 화면 스트림 보기. 원격 키보드·마우스 조작 기능은 포함하지 않음
- **배포 도구:** Windows 설치 프로그램, 업데이트 도구 및 PyInstaller 빌드 설정

## 구성

| 파일 | 용도 |
| --- | --- |
| `auto_shutdown.py` | Windows PC용 주 프로그램 |
| `auto_shutdown_runner.py` | 백그라운드 실행 지원 |
| `custom_server.py` | 자체 연결 서버 |
| `dashboard.html`, `index.html` | 브라우저 관리 화면 |
| `installer.py`, `updater.py` | 설치·업데이트 관련 코드 |
| `database.rules.json`, `firebase.json` | Firebase 설정과 규칙 |
| `tests/` | 보안·세션·대시보드·런타임 테스트 |

## 시작하기

1. Windows PC에서 저장소를 내려받고 프로그램에 필요한 Python 의존성 또는 제공된 빌드 실행 파일을 준비합니다.
2. 사용할 연결 방식에 맞게 Firebase 및 자체 서버 설정을 구성합니다. **실제 토큰·비밀번호·서비스 계정은 Git에 올리지 마세요.**
3. 관리 대상 PC에서 에이전트를 실행하고, 관리자 계정으로 `dashboard.html`을 통해 접속합니다.
4. 첫 실제 전원 제어 전에는 테스트 PC에서 권한과 연결 상태를 확인하세요.

소스 검증 명령:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
node tests/dashboard.test.cjs
node tests/session.test.cjs
```

브라우저 테스트에는 별도 브라우저/Playwright 환경이 필요할 수 있습니다. 자세한 변경 내용은 [OPTIMIZATION.md](OPTIMIZATION.md), 보안 검토는 [SECURITY_REVIEW.md](SECURITY_REVIEW.md)를 참고하세요.

> **주의:** 종료·재시작과 자동 로그인 설정은 실제 PC 상태에 영향을 줍니다. 관리자 권한과 Windows 보안 정책을 확인하고, 인증 없이 대시보드나 제어 서버를 인터넷에 노출하지 마세요. 저장소의 실행 파일이 항상 최신 소스와 동일하다고 가정하지 마세요.
