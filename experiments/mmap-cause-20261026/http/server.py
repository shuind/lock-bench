"""Persistent file checksum service; fresh read-only mmap for every request."""
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import mmap
import os
from pathlib import Path
import queue
import signal
import socket
import socketserver
import sys
import threading

FIXTURES=Path(__file__).resolve().parent.parent/'fixtures'
MANIFEST=json.loads((FIXTURES/'manifest.json').read_text())
FILES=MANIFEST['files']
assert [f['id'] for f in FILES]==list(range(4))
STOP=False
if os.environ.get("DIAGNOSTIC_SERVICE_CPUS"):
    os.sched_setaffinity(0,{int(x) for x in os.environ["DIAGNOSTIC_SERVICE_CPUS"].split(",")})
WORKERS=int(os.environ.get("HTTP_WORKERS","32"))
assert WORKERS in (1,32)

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def do_GET(self):
        if self.path not in ('/checksum/0','/checksum/1','/checksum/2','/checksum/3'):
            self.send_error(404);return
        item=FILES[int(self.path[-1])]
        # The result is computed from the fresh mapping. No cached digest is
        # used as the response, and no full byte-array copy is made.
        with (FIXTURES/item['name']).open('rb') as file:
            with mmap.mmap(file.fileno(),item['bytes'],access=mmap.ACCESS_READ) as region:
                digest=hashlib.sha256(region).hexdigest()
        if digest!=item['sha256']:self.send_error(500);return
        body=(digest+'\n').encode('ascii')
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)

class PoolServer(socketserver.TCPServer):
    allow_reuse_address=True
    request_queue_size=128
    def __init__(self):
        super().__init__(('127.0.0.1',0),Handler)
        self.timeout=.05;self.jobs=queue.Queue();self.worker_tids=[]
        self.workers=[threading.Thread(target=self.worker,name=f'http-{i}',daemon=True) for i in range(WORKERS)]
        for thread in self.workers:thread.start()
        while len(self.worker_tids)!=WORKERS:
            threading.Event().wait(.001)
    def worker(self):
        self.worker_tids.append(threading.get_native_id())
        while True:
            item=self.jobs.get()
            if item is None:return
            request,address=item
            try:self.finish_request(request,address)
            except Exception:self.handle_error(request,address)
            finally:self.shutdown_request(request)
    def process_request(self,request,address):self.jobs.put((request,address))
    def get_request(self):
        request,address=super().get_request()
        request.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        return request,address
    def close_pool(self):
        self.server_close()
        for _ in self.workers:self.jobs.put(None)
        for thread in self.workers:thread.join(timeout=3)

def stop(*args):
    global STOP
    STOP=True
def main():
    ready=Path(sys.argv[1])
    # Verify/cache the complete data set before readiness and before probes.
    for item in FILES:
        data=(FIXTURES/item['name']).read_bytes()
        assert len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256']
    del data
    server=PoolServer()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    temporary=ready.with_suffix('.tmp')
    temporary.write_text(json.dumps(dict(pid=os.getpid(),port=server.server_address[1],
        worker_tids=sorted(server.worker_tids),response_bytes=65,file_bytes=MANIFEST['file_bytes'],
        file_sha256=[f['sha256'] for f in FILES],file_cache_warmed=True,
        maps_per_request=1,endpoint='/checksum/<id>')))
    os.replace(temporary,ready)
    try:
        while not STOP:server.handle_request()
    finally:server.close_pool()
if __name__=='__main__':main()
