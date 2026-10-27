"""Local Chrome smoke test using production window controls and termination code.

Only accepts close commands for the explicitly selected local Whale window.
No Firebase requests or other remote commands are made.
"""
import ast
import ctypes
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security import kill_remote_process

TARGET_HWND = int(sys.argv[1])
pid = wintypes.DWORD()
ctypes.windll.user32.GetWindowThreadProcessId(wintypes.HWND(TARGET_HWND), ctypes.byref(pid))
TARGET_PID = pid.value
assert psutil.Process(TARGET_PID).name().lower() == 'whale.exe'
source = ast.parse((ROOT / 'auto_shutdown.py').read_text(encoding='utf-8'))
close = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'force_close_window')
exec(compile(ast.Module(body=[close], type_ignores=[]), str(ROOT / 'auto_shutdown.py'), 'exec'))
html = (ROOT / 'index.html').read_text(encoding='utf-8')
renderer = html.split('function renderWindowsList(list) {', 1)[1].split('\nfunction filterWindowsList()', 1)[0]
css = html.split('<style>', 1)[1].split('</style>', 1)[0]
page = '''<!doctype html><html lang="ko"><meta charset="utf-8"><title>실행창 강제 종료 실측</title>
<style>CSS</style><body style="padding:30px"><h1>이 컴퓨터 · 실행창 강제 종료 테스트</h1>
<p>실제 네이버 웨일 창을 종료합니다. Chrome은 유지됩니다.</p>
<div id="wm-list-container"></div><p id="result">종료 전 · 네이버 웨일 실행 중</p>
<dialog id="confirmation"><h2 id="title"></h2><p id="message"></p>
<button id="cancel">취소</button><button id="confirm">강제 종료</button></dialog>
<script>
const escapeHtml = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let confirmed;
async function _checkAuthPermission() { return true; }
function showModal(title, content, callback) {
 document.getElementById('title').textContent=title;
 document.getElementById('message').textContent=content;
 confirmed=callback; document.getElementById('confirmation').showModal();
}
function closeModal() { document.getElementById('confirmation').close(); }
async function writeCommandToDB(pc, action, data) {
 const r=await fetch('/close', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,...data})});
 const result=await r.json();
 document.getElementById('result').textContent=result.success ? '검증 통과 · 네이버 웨일 프로세스 종료 확인 · Chrome 유지' : '검증 실패: '+result.error;
 return result;
}
function renderWindowsList(list) {RENDERER
document.getElementById('cancel').onclick=closeModal;
document.getElementById('confirm').onclick=()=>confirmed();
document.addEventListener('click', event => {
 const btn=event.target.closest('[data-action="triggerWindowCommand"]');
 if(btn) triggerWindowCommand('LOCAL-TEST',btn.dataset.cmd,{hwnd:parseInt(btn.dataset.hwnd)},btn.dataset.title,btn.dataset.msg);
});
renderWindowsList(WINDOWS);
</script></body></html>'''.replace('CSS', css).replace('RENDERER', renderer).replace('WINDOWS', json.dumps([
    dict(hwnd=TARGET_HWND, pid=TARGET_PID, exe='whale.exe', title='새 탭 - Whale')
], ensure_ascii=False)).encode('utf-8')


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        try:
            assert self.path == '/close'
            assert self.headers.get('Origin') == 'http://127.0.0.1:8874'
            data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert data == dict(action='close_window', hwnd=TARGET_HWND)
            target = psutil.Process(TARGET_PID)
            assert target.name().lower() == 'whale.exe'
            assert force_close_window(TARGET_HWND)
            target.wait(timeout=10)
            result = dict(success=True)
            print(f'PASS: Whale PID {TARGET_PID} exited after Chrome close_window command', flush=True)
        except Exception as error:
            result = dict(success=False, error=str(error))
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())


print(f'Local test ready: http://127.0.0.1:8874, Whale PID={TARGET_PID}', flush=True)
ThreadingHTTPServer(('127.0.0.1', 8874), Handler).serve_forever()
