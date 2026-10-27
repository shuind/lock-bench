"""Start/warm fixed service and clients; synchronize only the request window."""
import hashlib
import http.client
import json
import multiprocessing as mp
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
MANIFEST=json.loads((HERE.parent/'fixtures/manifest.json').read_text())
FILES=MANIFEST['files']
MAGIC=0x53544541
def receive(pipe):
    if not pipe.poll(600):raise TimeoutError('Client timeout')
    data=pipe.recv()
    if 'error' in data:raise RuntimeError(data['error'])
    return data
def client(pipe,port,index):
    os.close(int(os.environ['BENCH_PHASE_FD']))
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
    try:
        connection.connect();pipe.send(dict(pid=os.getpid(),ready=True))
        while True:
            count=pipe.recv()
            if count is None:break
            begin=time.monotonic_ns();cpu=time.process_time_ns();latencies=[]
            files_checked=[0]*4
            for sequence in range(count):
                file_id=(index+sequence)%4
                t=time.monotonic_ns();connection.request('GET',f'/checksum/{file_id}')
                response=connection.getresponse();body=response.read()
                if response.status!=200 or body!=(FILES[file_id]['sha256']+'\n').encode('ascii'):
                    raise RuntimeError('Response verification failed')
                files_checked[file_id]+=1
                latencies.append(time.monotonic_ns()-t)
            pipe.send(dict(pid=os.getpid(),requests=count,bytes=count*65,
                file_bytes_checked=count*MANIFEST['file_bytes'],files_checked=files_checked,
                cpu_ns=time.process_time_ns()-cpu,wall_ns=time.monotonic_ns()-begin,
                latency_sum_ns=sum(latencies),latency_max_ns=max(latencies),verified=True))
    except BaseException as exc:
        try:pipe.send(dict(error=repr(exc)))
        except (EOFError,BrokenPipeError):pass
        raise
    finally:connection.close();pipe.close()
def main():
    requests,clients,warmup=map(int,sys.argv[1:4]);directory=Path(sys.argv[4]).resolve()
    if clients not in (1,32) or requests%clients or requests<clients:raise ValueError('Invalid request plan')
    directory.relative_to(HERE.parent);directory.mkdir(exist_ok=True)
    fd=int(os.environ['BENCH_PHASE_FD']);ready=directory/'ready.json'
    service=None;workers=[];pipes=[];log=None
    def interrupted(*args):raise SystemExit(143)
    signal.signal(signal.SIGTERM,interrupted)
    try:
        log=(directory/'server.log').open('w')
        service=subprocess.Popen(['/usr/bin/python3',str(HERE/'server.py'),str(ready)],stdout=log,stderr=log)
        deadline=time.monotonic()+15
        while not ready.exists():
            if service.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Service not ready')
            time.sleep(.002)
        info=json.loads(ready.read_text());assert info['pid']==service.pid and len(info['worker_tids'])==clients
        ctx=mp.get_context('fork')
        for index in range(clients):
            parent,child=ctx.Pipe();process=ctx.Process(target=client,args=(child,info['port'],index))
            process.start();child.close();workers.append(process);pipes.append(parent)
        identities=[receive(pipe)['pid'] for pipe in pipes]
        for pipe in pipes:pipe.send(warmup)
        warmed=[receive(pipe) for pipe in pipes]
        assert all(row['verified'] and row['requests']==warmup for row in warmed)
        # Ensure previous response handling is quiescent before loading probes.
        time.sleep(.05)
        os.write(fd,struct.pack('=Iii32i',MAGIC,clients,service.pid,*(identities+[0]*(32-clients))))
        if os.read(fd,1)!=b'G':raise RuntimeError('Missing measurement start')
        for pipe in pipes:pipe.send(requests//clients)
        measured=[receive(pipe) for pipe in pipes]
        assert sum(row['requests'] for row in measured)==requests
        os.write(fd,b'D')
        if os.read(fd,1)!=b'F':raise RuntimeError('Missing measurement finish')
        # Serialization, closing connections and process teardown are outside
        # both CPU/window snapshots and probe attachment.
        assert sum(row['file_bytes_checked'] for row in measured)==requests*MANIFEST['file_bytes']
        result=dict(service=info,clients=clients,requests=requests,bytes=requests*65,
            file_bytes_checked=requests*MANIFEST['file_bytes'],maps_created=requests,
            files_checked=[sum(row['files_checked'][i] for row in measured) for i in range(4)],
            warmup_per_client=warmup,client_results=measured,verified=True)
        for pipe in pipes:pipe.send(None)
        for process in workers:
            process.join(timeout=10)
            if process.exitcode!=0:raise RuntimeError('Client failed to exit')
        service.terminate();service.wait(timeout=10)
        if service.returncode!=0:raise RuntimeError('Service failed to exit')
        print(json.dumps(result),flush=True)
    finally:
        for pipe in pipes:pipe.close()
        for process in workers:
            if process.is_alive():process.terminate();process.join(timeout=5)
        if service is not None and service.poll() is None:
            service.terminate()
            try:service.wait(timeout=10)
            except subprocess.TimeoutExpired:service.kill();service.wait()
        if log is not None:log.close()
        os.close(fd)
if __name__=='__main__':main()
