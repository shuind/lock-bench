"""HTTP lifecycle and persistent file-checksum workloads."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import mmap
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

PAYLOAD = b'lockbench\n' * 3641
PAYLOAD = (PAYLOAD + b' ' * 32768)[:32768]


def server(ready, folder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        disable_nagle_algorithm = True

        def log_message(self, *args):
            pass

        def do_GET(self):
            if folder and self.path.startswith('/checksum/'):
                try:
                    index = int(self.path.rsplit('/', 1)[-1])
                except ValueError:
                    self.send_error(404)
                    return
                if index not in range(4):
                    self.send_error(404)
                    return
                with (folder / f'file-{index}.dat').open('rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as region:
                        body = (hashlib.sha256(region).hexdigest() + '\n').encode()
            elif self.path == '/payload':
                body = PAYLOAD
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()

        def do_POST(self):
            if self.path != '/shutdown':
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()
            threading.Thread(target=httpd.shutdown, daemon=True).start()

    class Server(ThreadingHTTPServer):
        request_queue_size = 128

    httpd = Server(('127.0.0.1', 0), Handler)
    httpd.daemon_threads = True
    ready.write_text(json.dumps(dict(pid=os.getpid(), port=httpd.server_port)))
    try:
        httpd.serve_forever(poll_interval=0.01)
    finally:
        httpd.server_close()


def spawn(session, index, folder=None):
    ready = session.args.workdir / f'server-{index}.json'
    ready.unlink(missing_ok=True)
    log = (session.args.workdir / f'server-{index}.log').open('w')
    try:
        p = session.watch(
            subprocess.Popen(
                [
                    sys.executable,
                    '-m',
                    'workload.http_service',
                    str(ready),
                    str(folder) if folder else '-',
                ],
                stdout=log,
                stderr=log,
                cwd=Path(__file__).resolve().parents[1],
            )
        )
    finally:
        log.close()
    deadline = time.monotonic() + 15
    while not ready.exists():
        if p.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError('HTTP service readiness failed')
        time.sleep(0.002)
    return p, json.loads(ready.read_text())['port']


def fetch(connection, path, expected):
    connection.request('GET', path)
    response = connection.getresponse()
    body = response.read()
    if response.status != 200 or body != expected:
        raise RuntimeError('HTTP response mismatch')


def stop(process, connection):
    try:
        connection.request('POST', '/shutdown')
        response = connection.getresponse()
        response.read()
        if response.status != 200:
            raise RuntimeError('HTTP shutdown failed')
    finally:
        connection.close()
    if process.wait(timeout=5):
        raise RuntimeError('HTTP service exit failed')


def execute(session):
    args = session.args
    if args.workload == 'http':
        session.ready(concurrency=args.concurrency, requests_per_service=4)
        counter = 0
        lock = threading.Lock()
        deadline = time.monotonic() + args.duration

        def lifecycle(worker):
            nonlocal counter
            completed = 0
            while True:
                with lock:
                    if args.operations and counter >= args.operations:
                        break
                    if not args.operations and time.monotonic() >= deadline:
                        break
                    index = counter
                    counter += 1
                p, port = spawn(session, index)
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                for _ in range(4):
                    fetch(connection, '/payload', PAYLOAD)
                stop(p, connection)
                completed += 1
            return completed

        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            counts = list(pool.map(lifecycle, range(args.concurrency)))
        session.result(
            sum(counts),
            unit='service-lifecycles',
            requests=4 * sum(counts),
            response_bytes=32768 * 4 * sum(counts),
        )
        return
    folder = args.workdir / 'files'
    folder.mkdir()
    expected = []
    for index in range(4):
        block = bytes([index + 1]) * 1048576
        digest = hashlib.sha256()
        with (folder / f'file-{index}.dat').open('wb') as stream:
            for _ in range(args.file_mib):
                stream.write(block)
                digest.update(block)
        expected.append((digest.hexdigest() + '\n').encode())
    p, port = spawn(session, 0, folder)
    gate = threading.Event()
    condition = threading.Condition()
    prepared = 0
    errors = []
    start = 0

    def client(index):
        nonlocal prepared
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
        try:
            fetch(connection, f'/checksum/{index%4}', expected[index % 4])
            with condition:
                prepared += 1
                condition.notify_all()
            gate.wait()
            done = 0
            limit = args.operations // args.concurrency + (
                index < args.operations % args.concurrency
            )
            while done < limit if args.operations else time.monotonic() < start + args.duration:
                file = (index + done) % 4
                fetch(connection, f'/checksum/{file}', expected[file])
                done += 1
            return done
        except BaseException as exc:
            with condition:
                errors.append(exc)
                condition.notify_all()
            raise
        finally:
            connection.close()

    pool = ThreadPoolExecutor(max_workers=args.concurrency)
    futures = [pool.submit(client, i) for i in range(args.concurrency)]
    try:
        with condition:
            if not condition.wait_for(lambda: prepared == args.concurrency or errors, timeout=40):
                raise TimeoutError('Client warmup timed out')
            if errors:
                raise errors[0]
        session.ready(
            service_pid=p.pid, clients=args.concurrency, file_bytes=args.file_mib * 1024**2
        )
        start = time.monotonic()
        gate.set()
        counts = [f.result() for f in futures]
        session.result(
            sum(counts),
            unit='requests',
            file_bytes_checked=sum(counts) * args.file_mib * 1024**2,
            response_bytes=sum(counts) * 65,
            mappings=sum(counts),
            client_counts=counts,
        )
    finally:
        gate.set()
        pool.shutdown(wait=True)
        if p.poll() is None:
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            stop(p, connection)
        for f in folder.glob('file-*.dat'):
            f.unlink()
        folder.rmdir()


if __name__ == '__main__':
    server(Path(sys.argv[1]), Path(sys.argv[2]) if sys.argv[2] != '-' else None)
