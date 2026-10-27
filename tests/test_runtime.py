"""Exercise isolated algorithms without starting the app, networking or power actions."""
import ast
import copy
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

SOURCE = ast.parse((Path(__file__).resolve().parents[1] / 'auto_shutdown.py').read_text(encoding='utf-8'))

def extract(name, class_name=None):
    nodes = SOURCE.body
    if class_name:
        nodes = next(node for node in nodes if isinstance(node, ast.ClassDef) and node.name == class_name).body
    return next(node for node in nodes if isinstance(node, ast.FunctionDef) and node.name == name)

def load(node, namespace):
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<isolated source>', 'exec'), namespace)
    return namespace[node.name]

class RuntimeTests(unittest.TestCase):
    def test_force_close_window_resolves_owner_and_forces_process_exit(self):
        user32, kill = Mock(), Mock()
        namespace = dict(ctypes=SimpleNamespace(sizeof=ctypes.sizeof, byref=ctypes.byref,
                                                windll=SimpleNamespace(user32=user32)),
                         wintypes=wintypes, kill_remote_process=kill)
        close = load(extract('force_close_window'), namespace)

        def resolve(hwnd, pid):
            self.assertEqual(hwnd.value, 123)
            pid._obj.value = 456
            return 1

        user32.GetWindowThreadProcessId.side_effect = resolve
        self.assertTrue(close('123'))
        kill.assert_called_once_with(456)
        user32.PostMessageW.assert_not_called()
        kill.reset_mock()
        user32.GetWindowThreadProcessId.reset_mock(side_effect=True)
        for hwnd in [None, True, 0, -1, 'invalid', {}, 1 << (ctypes.sizeof(wintypes.HWND) * 8)]:
            with self.subTest(hwnd=hwnd):
                self.assertFalse(close(hwnd))
        user32.GetWindowThreadProcessId.assert_not_called()
        user32.GetWindowThreadProcessId.return_value = 0
        self.assertFalse(close(123))
        user32.GetWindowThreadProcessId.return_value = 1
        self.assertFalse(close(123))  # No owning PID returned.
        kill.assert_not_called()

    def test_all_close_window_command_routes_force_close(self):
        routes = [node for node in ast.walk(SOURCE) if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "action == 'close_window' and isinstance(message, dict)"]
        self.assertEqual(len(routes), 4)
        for route in routes:
            branch = copy.deepcopy(route)
            branch.orelse = []
            close = Mock(return_value=True)
            namespace = dict(action='close_window', message={'hwnd': 123}, force_close_window=close)
            exec(compile(ast.Module(body=[branch], type_ignores=[]), '<command route>', 'exec'), namespace)
            close.assert_called_once_with(123)

    def test_config_cache_refresh_isolation_and_partial_write(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            filename = Path(folder) / 'config.json'
            namespace = dict(os=os, json=json, CONFIG_FILE=str(filename),
                             _config_cache_lock=threading.Lock(), _config_cache_stamp=None, _config_cache_data={})
            read = load(extract('read_runtime_config'), namespace)
            self.assertEqual(read(), {})
            filename.write_text('{"nested":{"value":1}}', encoding='utf-8')
            result = read()
            result['nested']['value'] = 9
            self.assertEqual(read()['nested']['value'], 1)
            filename.write_text('{', encoding='utf-8')
            self.assertEqual(read()['nested']['value'], 1)
            filename.write_text('{"nested":{"value":123}}', encoding='utf-8')
            self.assertEqual(read()['nested']['value'], 123)

    def test_lead_time_crosses_midnight(self):
        class FixedDateTime(datetime):
            @classmethod
            def now(cls):
                return cls(2026, 10, 19, 23, 40)
        for class_name in ['AutoShutdownAppV2', 'HeadlessShutdownApp']:
            with self.subTest(class_name=class_name):
                namespace = dict(datetime=FixedDateTime, timedelta=timedelta,
                                 DAYS=['월', '화', '수', '목', '금', '토', '일'], TIMETABLE={'첫 예약': '00:10'})
                calculate = load(extract('get_next_event', class_name), namespace)
                config = {'minutes_before': 30, '화': {'첫 예약': {'enabled': True, 'action': '재부팅'}}}
                app = SimpleNamespace(load_config=lambda: config, skipped_events=set())
                when, action = calculate(app)
                self.assertEqual(when, datetime(2026, 10, 19, 23, 40))
                self.assertEqual(action, '재부팅')

    def test_headless_restart_dispatch_and_no_repeat(self):
        target = datetime.now().replace(second=0, microsecond=0)
        calls = Mock()
        app = SimpleNamespace(is_running=True, get_next_event=lambda: (target, '재부팅'), last_triggered_time=None)
        ticks = []
        def sleep(_):
            ticks.append(1)
            if len(ticks) == 2:
                app.is_running = False
        namespace = dict(datetime=datetime, time=SimpleNamespace(sleep=sleep),
                         subprocess=SimpleNamespace(run=calls, CREATE_NO_WINDOW=0))
        monitor = load(extract('monitor_time', 'HeadlessShutdownApp'), namespace)
        monitor(app)
        calls.assert_called_once_with(['shutdown', '/r', '/t', '0'], creationflags=0)

if __name__ == '__main__':
    unittest.main()
