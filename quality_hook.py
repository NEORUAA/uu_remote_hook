"""Discover and apply a reversible quality-cap hook to compatible UU Remote clients."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
from locator import discover, UnsupportedImplementation


def process_path(pid):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_ulong(len(buffer))
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return Path(buffer.value)
    finally:
        kernel.CloseHandle(handle)


class Controller:
    def __init__(self, state_dir, startup_token=None):
        self.state = state_dir
        self.startup_token = startup_token
        self.done = threading.Event()
        self.sessions = {}
        self.lock = threading.RLock()
        self.mutex = None

    def record(self, event):
        line = json.dumps({'time': datetime.now(timezone.utc).isoformat(), **event}, ensure_ascii=True)
        with self.lock:
            print(line, flush=True)
            with (self.state / 'events.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(line + '\n')

    def status(self, phase, **fields):
        with self.lock:
            value = {'controller_pid': os.getpid(), 'startup_token': self.startup_token, 'phase': phase, **fields}
            temporary = self.state / 'status.tmp'
            temporary.write_text(json.dumps(value), encoding='utf-8')
            temporary.replace(self.state / 'status.json')

    def acquire(self):
        import hashlib
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = ctypes.c_void_p
        name = hashlib.sha256(str(self.state.resolve()).lower().encode()).hexdigest()
        ctypes.set_last_error(0)
        self.mutex = kernel.CreateMutexW(None, False, 'Local\\UUQualityHook-' + name)
        if not self.mutex:
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == 183:
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel.CloseHandle(self.mutex)
            self.mutex = None
            raise RuntimeError('A controller is already running for this state directory.')
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / 'stop').unlink(missing_ok=True)
        (self.state / 'controller.pid').write_text(str(os.getpid()), encoding='ascii')

    def attach(self, device, pid):
        path = process_path(pid)
        profile = discover(path)
        session = device.attach(pid)
        script = session.create_script((ROOT / 'quality_hook.js').read_text(encoding='utf-8'))
        def on_message(message, data):
            if message['type'] == 'send':
                self.record({'target_pid': pid, **message['payload']})
            elif message['type'] == 'error':
                self.record({'event': 'script_error', 'target_pid': pid, 'detail': message.get('stack', message)})
        script.on('message', on_message)
        def on_detached(reason, crash=None):
            with self.lock:
                self.sessions.pop(pid, None)
            self.record({'event': 'detached', 'target_pid': pid, 'reason': reason})
        session.on('detached', on_detached)
        try:
            script.load()
            result = script.exports_sync.install(path.name, profile.to_dict())
            if not result['installed']:
                raise RuntimeError('The script did not confirm a successful installation.')
            with self.lock:
                self.sessions[pid] = (session, script)
            self.record({'event': 'attached', 'sha256': profile.sha256, **result})
        except Exception:
            session.detach()
            raise

    def run(self, pid=None):
        import frida
        self.acquire()
        failures = {}
        signal.signal(signal.SIGINT, lambda *_: self.done.set())
        signal.signal(signal.SIGTERM, lambda *_: self.done.set())
        try:
            self.record({'event': 'controller_started', 'pid': os.getpid()})
            self.status('starting')
            device = frida.get_local_device()
            while not self.done.is_set() and not (self.state / 'stop').exists():
                targets = [p for p in device.enumerate_processes() if p.name.lower() == 'gameviewer.exe' and (pid is None or p.pid == pid)]
                for process in targets:
                    with self.lock:
                        attached = process.pid in self.sessions
                    if attached or time.monotonic() - failures.get(process.pid, (0, ''))[0] < 30:
                        continue
                    try:
                        self.attach(device, process.pid)
                        failures.pop(process.pid, None)
                    except Exception as error:
                        previous = failures.get(process.pid)
                        message = str(error)
                        if not previous or previous[1] != message:
                            self.record({'event': 'attach_failed', 'target_pid': process.pid, 'detail': message})
                        failures[process.pid] = (time.monotonic(), message)
                with self.lock:
                    attached_pids = sorted(self.sessions)
                if attached_pids:
                    self.status('ready', target_pids=attached_pids)
                elif targets:
                    self.status('unsupported', detail='No compatible client could be attached. See events.jsonl.')
                else:
                    self.status('waiting', detail='Waiting for GameViewer.exe.')
                self.done.wait(2)
        finally:
            with self.lock:
                active = list(self.sessions.values())
            for session, script in active:
                try:
                    self.record({'event': 'hook_removed', **script.exports_sync.stop()})
                    script.unload()
                    session.detach()
                except Exception as error:
                    self.record({'event': 'cleanup_error', 'detail': str(error)})
            self.status('stopped')
            (self.state / 'controller.pid').unlink(missing_ok=True)
            (self.state / 'stop').unlink(missing_ok=True)
            self.record({'event': 'controller_stopped'})
            if self.mutex:
                kernel = ctypes.WinDLL('kernel32')
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel.CloseHandle(self.mutex)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, help='Attach only to this client PID.')
    parser.add_argument('--check', action='store_true', help='Inspect compatibility without injecting.')
    parser.add_argument('--exe', type=Path, help='Inspect an extracted executable with --check.')
    parser.add_argument('--state-dir', type=Path, default=ROOT / '.runtime')
    parser.add_argument('--startup-token', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.exe and not args.check:
        parser.error('--exe requires --check; executable files are never launched.')
    if args.check and args.exe:
        try:
            print(json.dumps({'compatible': True, **discover(args.exe).to_dict()}))
            return 0
        except (UnsupportedImplementation, OSError, ValueError) as error:
            print(json.dumps({'compatible': False, 'detail': str(error)}))
            return 1
    if sys.platform != 'win32':
        parser.error('Live process operations require Windows.')
    if args.check:
        import frida
        targets = [p for p in frida.get_local_device().enumerate_processes() if p.name.lower() == 'gameviewer.exe' and (args.pid is None or p.pid == args.pid)]
        if not targets:
            print('No GameViewer.exe process is running.', file=sys.stderr)
            return 1
        failed = False
        for process in targets:
            try:
                print(json.dumps({'pid': process.pid, 'compatible': True, **discover(process_path(process.pid)).to_dict()}))
            except Exception as error:
                print(json.dumps({'pid': process.pid, 'compatible': False, 'detail': str(error)}))
                failed = True
        return int(failed)
    Controller(args.state_dir.resolve(), args.startup_token).run(args.pid)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as error:
        print(f'Error: {error}', file=sys.stderr)
        raise SystemExit(1)
