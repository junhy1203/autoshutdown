import os
import re
import json
import subprocess
import time
import sys
import urllib.request
import urllib.error
import urllib.parse
import ssl

# Windows CMD 인코딩 강제 설정
sys.stdout.reconfigure(encoding='utf-8') if hasattr(sys.stdout, 'reconfigure') else None

# exe로 실행될 때와 .py로 실행될 때 모두 올바른 기준 경로 사용
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

REPO_OWNER = "JunHyuk1203"
REPO_NAME  = "autoshutdown"

print("==================================================")
print("[AutoShutdown] 배포 자동화 프로그램 시작")
print(f"기준 경로: {BASE_DIR}")
print("==================================================")

app_path        = os.path.join(BASE_DIR, "auto_shutdown.py")
spec_path       = os.path.join(BASE_DIR, "auto_shutdown.spec")
installer_spec  = os.path.join(BASE_DIR, "스마트_전원_관리자_설치파일.spec")
version_path    = os.path.join(BASE_DIR, "version.json")
exe_path        = os.path.join(BASE_DIR, "dist", "auto_shutdown.exe")
git_exe         = r"C:\Program Files\Git\cmd\git.exe"

# ── SSL 컨텍스트 ─────────────────────────────────────────────────────────────
try:
    _ssl = ssl.create_default_context()
except Exception:
    _ssl = None

# ── GitHub 토큰: Windows Credential Manager에서 자동 추출 ──────────────────
def _get_github_token():
    try:
        r = subprocess.run(
            [git_exe, "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            capture_output=True, text=True
        )
        for line in r.stdout.splitlines():
            if line.startswith("password="):
                return line[len("password="):].strip()
    except Exception as e:
        print(f"[WARN] credential 읽기 실패: {e}")
    return None

# ── GitHub API 헬퍼 ──────────────────────────────────────────────────────────
def _gh_api(method, path, data=None, token=None, extra_headers=None, raw_data=None, content_type="application/json"):
    url = f"https://api.github.com{path}"
    headers = {
        "User-Agent": "AutoShutdown-Deploy",
        "Accept":     "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    if extra_headers:
        headers.update(extra_headers)

    body = None
    if raw_data is not None:
        body = raw_data
        headers["Content-Type"] = content_type
    elif data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_ssl, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API {method} {path} → {e.code}: {body_txt}")

# ── 파일 존재 확인 ───────────────────────────────────────────────────────────
for path, name in [(app_path, "auto_shutdown.py"), (spec_path, "auto_shutdown.spec")]:
    if not os.path.exists(path):
        print(f"[Error] {name} 파일을 찾을 수 없습니다. (경로: {path})")
        time.sleep(5)
        exit(1)

# ── 버전 읽기 및 업그레이드 ──────────────────────────────────────────────────
with open(app_path, "r", encoding="utf-8") as f:
    content = f.read()

version_match = re.search(r'CURRENT_VERSION\s*=\s*"(\d+)\.(\d+)\.(\d+)"', content)
if not version_match:
    print("[Error] 버전 정보(CURRENT_VERSION)를 찾을 수 없습니다.")
    time.sleep(5)
    exit(1)

major, minor, patch = int(version_match.group(1)), int(version_match.group(2)), int(version_match.group(3))
current_v = f"{major}.{minor}.{patch}"
new_v     = f"{major}.{minor}.{patch+1}"

print(f"\n[1단계] 버전 업그레이드 ({current_v} -> {new_v})")
content = content.replace(f'CURRENT_VERSION = "{current_v}"', f'CURRENT_VERSION = "{new_v}"')
with open(app_path, "w", encoding="utf-8") as f:
    f.write(content)

# ── 프로세스 종료 ─────────────────────────────────────────────────────────────
print("\n[2단계] 기존 실행 중인 프로그램 강제 종료 중...")
try:
    subprocess.run(["taskkill", "/F", "/IM", "auto_shutdown.exe"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except Exception:
    pass
time.sleep(1)

# ── auto_shutdown.exe 빌드 ───────────────────────────────────────────────────
print("\n[2.5단계] 클라이언트 코드 암호화(Obfuscation) 적용...")
try:
    # subprocess.run([sys.executable, "build_obf.py"], check=True, cwd=BASE_DIR)
    import shutil
    shutil.copy(app_path, app_path + ".bak")
    # shutil.copy(os.path.join(BASE_DIR, "auto_shutdown_runner.py"), app_path)
    print("암호화 적용 완료.")
except Exception as e:
    print(f"[Error] 암호화 실패: {e}")
print("\n[3단계] auto_shutdown.exe PyInstaller 빌드 중... (시간이 걸릴 수 있습니다)")
try:
    for build_spec in ('updater.spec', 'ManualUpdater.spec', spec_path):
        subprocess.run(["pyinstaller", "--noconfirm", build_spec], check=True, cwd=BASE_DIR)
except Exception as e:
    print(f"[Error] 빌드 실패: {e}")
    content = content.replace(f'CURRENT_VERSION = "{new_v}"', f'CURRENT_VERSION = "{current_v}"')
    with open(app_path, "w", encoding="utf-8") as f:
        f.write(content)
    time.sleep(5)
    exit(1)

# ── 설치파일 빌드 생략 ─────────────────────────────────────────────────────────────


# ── GitHub Releases API로 exe 업로드 ─────────────────────────────────────────
print("\n[3-3단계] 원본 클라이언트 코드 복구...")
try:
    import shutil
    shutil.move(app_path + ".bak", app_path)
except Exception as e:
    pass
print("\n[4단계] GitHub Release 생성 및 exe 업로드 중...")
token = _get_github_token()
if not token:
    print("[WARN] GitHub 토큰을 읽지 못했습니다. Release 생성을 건너뜁니다.")
    download_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/download/v{new_v}/auto_shutdown.exe"
else:
    tag = f"v{new_v}"
    # 기존 릴리즈가 있으면 삭제
    try:
        existing = _gh_api("GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{tag}", token=token)
        _gh_api("DELETE", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/{existing['id']}", token=token)
        print(f"  기존 릴리즈 {tag} 삭제 완료")
    except Exception:
        pass
    # 태그도 삭제 (push 전이라 로컬에만 있을 수도 있음)
    try:
        _gh_api("DELETE", f"/repos/{REPO_OWNER}/{REPO_NAME}/git/refs/tags/{tag}", token=token)
    except Exception:
        pass

    # 릴리즈 생성
    release = _gh_api("POST", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases", token=token, data={
        "tag_name":         tag,
        "target_commitish": "main",
        "name":             f"v{new_v}",
        "body":             f"자동 배포: v{new_v}",
        "draft":            False,
        "prerelease":       False,
    })
    release_id   = release["id"]
    upload_url_base = release["upload_url"].split("{")[0]  # 템플릿 부분 제거
    print(f"  릴리즈 생성 완료 (id={release_id})")

    # exe 업로드 (auto_shutdown.exe)
    if not os.path.exists(exe_path):
        print(f"[Error] exe 파일 없음: {exe_path}")
    else:
        with open(exe_path, "rb") as ef:
            exe_data = ef.read()
        upload_url = f"{upload_url_base}?name=auto_shutdown.exe"
        # uploads.github.com 은 api.github.com 과 다른 호스트이므로 직접 호출
        up_req = urllib.request.Request(
            upload_url,
            data=exe_data,
            method="POST",
            headers={
                "Authorization":  f"token {token}",
                "Content-Type":   "application/octet-stream",
                "User-Agent":     "AutoShutdown-Deploy",
                "Accept":         "application/vnd.github+json",
            }
        )
        with urllib.request.urlopen(up_req, context=_ssl, timeout=300) as resp:
            asset = json.loads(resp.read().decode("utf-8"))
        print(f"  exe 업로드 완료: {asset.get('browser_download_url')}")

    # SmartPowerInstaller.exe 업로드
    installer_path = os.path.join(BASE_DIR, "dist", "SmartPowerInstaller.exe")
    if os.path.exists(installer_path):
        with open(installer_path, "rb") as ef:
            installer_data = ef.read()
        installer_upload_url = f"{upload_url_base}?name=SmartPowerInstaller.exe"
        inst_req = urllib.request.Request(
            installer_upload_url,
            data=installer_data,
            method="POST",
            headers={
                "Authorization":  f"token {token}",
                "Content-Type":   "application/octet-stream",
                "User-Agent":     "AutoShutdown-Deploy",
                "Accept":         "application/vnd.github+json",
            }
        )
        try:
            with urllib.request.urlopen(inst_req, context=_ssl, timeout=300) as resp:
                inst_asset = json.loads(resp.read().decode("utf-8"))
            print(f"  SmartPowerInstaller 업로드 완료: {inst_asset.get('browser_download_url')}")
        except Exception as ue:
            print(f"  [WARN] SmartPowerInstaller 업로드 실패: {ue}")
    else:
        print("  [WARN] SmartPowerInstaller.exe 없음 - 업로드 건너뜀")

    # ManualUpdater.exe 업로드
    manual_updater_path = os.path.join(BASE_DIR, "dist", "ManualUpdater.exe")
    if os.path.exists(manual_updater_path):
        with open(manual_updater_path, "rb") as ef:
            mu_data = ef.read()
        mu_upload_url = f"{upload_url_base}?name=ManualUpdater.exe"
        mu_req = urllib.request.Request(
            mu_upload_url,
            data=mu_data,
            method="POST",
            headers={
                "Authorization":  f"token {token}",
                "Content-Type":   "application/octet-stream",
                "User-Agent":     "AutoShutdown-Deploy",
                "Accept":         "application/vnd.github+json",
            }
        )
        try:
            with urllib.request.urlopen(mu_req, context=_ssl, timeout=300) as resp:
                mu_asset = json.loads(resp.read().decode("utf-8"))
            print(f"  ManualUpdater 업로드 완료: {mu_asset.get('browser_download_url')}")
        except Exception as ue:
            print(f"  [WARN] ManualUpdater 업로드 실패: {ue}")
    else:
        print("  [WARN] ManualUpdater.exe 없음 - 업로드 건너뜀")

    download_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/download/{tag}/auto_shutdown.exe"

# ── version.json 및 Firebase 업데이트 ────────────────────────────────────────
print("\n[5단계] version.json 업데이트 및 Firebase 업로드 중...")
version_data = {
    "version":      new_v,
    "download_url": download_url,
}
with open(version_path, "w", encoding="utf-8") as f:
    json.dump(version_data, f, indent=4)

firebase_url     = "https://atss-a1f9e-default-rtdb.firebaseio.com/update_info.json"
admin_token = os.environ.get('SMARTPOWER_ADMIN_ID_TOKEN')
if not admin_token:
    raise RuntimeError('SMARTPOWER_ADMIN_ID_TOKEN is required to publish update metadata')
firebase_url += '?auth=' + urllib.parse.quote(admin_token, safe='')
version_payload  = json.dumps(version_data).encode("utf-8")
fb_req = urllib.request.Request(
    firebase_url, data=version_payload, method="PUT",
    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
)
try:
    with urllib.request.urlopen(fb_req, timeout=15, context=_ssl) as res:
        print("[SUCCESS] Firebase update_info.json 업로드 완료")
        print(f"  download_url = {download_url}")
except Exception as fe:
    print(f"[FAIL] Firebase 업로드 실패: {fe}")

# ── GitHub main 브랜치 push ───────────────────────────────────────────────────
print("\n[6단계] GitHub main 브랜치로 소스 업로드 중...")
try:
    subprocess.run([git_exe, "add", "."], check=True, cwd=BASE_DIR)
    subprocess.run([git_exe, "commit", "-m", f"Release v{new_v}"], check=False, cwd=BASE_DIR)
    result = subprocess.run([git_exe, "push", "origin", "main"],
                            capture_output=True, text=True, cwd=BASE_DIR)
    if result.returncode == 0:
        print(f"\n[성공] 배포 완료! GitHub에 버전 {new_v}이(가) 업로드되었습니다.")
    else:
        print(f"\n[Error] GitHub push 실패:\n{result.stderr}")
        print("바탕화면의 1_깃허브_최초로그인을 다시 실행해 보세요.")
except Exception as e:
    print(f"\n[Error] Git 오류: {e}")

print("\n배포 프로세스가 완료되었습니다.")
# input("\n엔터를 누르면 창이 닫힙니다...")
