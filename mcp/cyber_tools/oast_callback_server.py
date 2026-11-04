"""Bounded local HTTP OAST collector. No fabricated DNS or third-party polling."""
import atexit
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

CALLBACKS = {}
_lock = threading.RLock()
_server = None
_thread = None
_TTL = 3600
_MAX_CALLBACKS = 256


def _prune():
    now = time.time()
    for key in list(CALLBACKS):
        if now - CALLBACKS[key]['generated_at'] > _TTL:
            del CALLBACKS[key]


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        cid = urlsplit(self.path).path.removeprefix('/oast/').strip('/')
        with _lock:
            _prune()
            entry = CALLBACKS.get(cid) if self.path.startswith('/oast/') else None
            if entry is not None:
                # Do not retain headers, query strings, body or arbitrary secrets.
                if len(entry['hits']) < 32:
                    entry['hits'].append({'callback_id': cid, 'protocol': 'http',
                                          'method': self.command, 'received_at': time.time()})
                entry['_event'].set()
        self.send_response(204 if entry is not None else 404)
        self.send_header('Content-Length', '0')
        self.end_headers()

    do_HEAD = do_GET

    def log_message(self, *_):
        pass


def _stop():
    global _server, _thread
    with _lock:
        server, thread = _server, _thread
        _server = _thread = None
        for entry in CALLBACKS.values():
            entry['_event'].set()
        CALLBACKS.clear()
    if server is not None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


atexit.register(_stop)


def oast_callback_server(action: str, payload: str = '', callback_id: str = '',
                         poll_url: str = '', max_wait: int = 15, platform: str = 'auto') -> str:
    global _server, _thread
    if poll_url:
        return json.dumps({'status': 'unsupported', 'error': 'External polling is not configured; this collector polls local correlated HTTP hits only'})
    if action == 'stop':
        _stop()
        return json.dumps({'status': 'stopped'})
    if action == 'start':
        with _lock:
            if _server is None:
                _server = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
                _server.daemon_threads = True
                _thread = threading.Thread(target=_server.serve_forever, daemon=True)
                _thread.start()
            return json.dumps({'status': 'listening', 'bind_url': f'http://127.0.0.1:{_server.server_port}',
                               'protocols': ['http'], 'dns_supported': False})
    with _lock:
        _prune()
        if action == 'clear':
            for entry in CALLBACKS.values():
                entry['_event'].set()
            CALLBACKS.clear()
            return json.dumps({'status': 'cleared'})
        if action == 'generate':
            if _server is None:
                return json.dumps({'status': 'not_configured', 'error': 'Call start to run the loopback HTTP collector. For remote targets configure CYBERSEC_OAST_PUBLIC_URL forwarding to this listener.'})
            if len(CALLBACKS) >= _MAX_CALLBACKS:
                return json.dumps({'status': 'capacity_exceeded', 'error': 'Clear expired/test callbacks before generating more'})
            public = os.environ.get('CYBERSEC_OAST_PUBLIC_URL', '').rstrip('/')
            if public:
                parsed = urlsplit(public)
                if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                    return json.dumps({'status': 'not_configured', 'error': 'Invalid CYBERSEC_OAST_PUBLIC_URL'})
            base = public or f'http://127.0.0.1:{_server.server_port}'
            cid = secrets.token_hex(16)
            url = f'{base}/oast/{cid}'
            entry = {'callback_id': cid, 'generated_at': time.time(), 'oob_urls': {'http': url},
                     'reachability': 'public_url_unverified' if public else 'loopback_only',
                     'protocols': ['http'], 'dns_supported': False, 'hits': [],
                     'payload': payload.replace('BURPCOLLABORATOR', url) if payload else url}
            CALLBACKS[cid] = {**entry, '_event': threading.Event()}
            return json.dumps(entry)
        entry = CALLBACKS.get(callback_id)
        if action in ('poll', 'status') and callback_id:
            if entry is None:
                return json.dumps({'error': 'Callback not found or expired', 'callback_id': callback_id})
            event = entry['_event']
        elif action == 'status':
            return json.dumps({'status': 'listening' if _server else 'stopped',
                               'total_callbacks': len(CALLBACKS), 'protocols': ['http'], 'dns_supported': False})
        else:
            return json.dumps({'error': 'Unknown action or missing callback_id',
                               'actions': ['start', 'stop', 'generate', 'poll', 'status', 'clear']})
    if action == 'poll':
        event.wait(max(0, min(int(max_wait), 30)))
    with _lock:
        hits = list(entry['hits'])
    return json.dumps({'callback_id': callback_id, 'received': bool(hits),
                       'interaction_found': bool(hits), 'hits': hits, 'total_hits': len(hits),
                       'coverage': 'correlated HTTP callbacks only; no DNS polling',
                       'reachability': entry['reachability']})
