"""Opt-in real socket test. Starts/stops only its own temporary localhost server.
Run: .venv/bin/python scripts/smoke_live.py
"""
import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen

REEL = 'https://www.instagram.com/reel/DdQ90KiyERI/'
CAROUSEL = 'https://www.instagram.com/p/DdEZgWTlGfB/'
YOUTUBE = 'https://www.youtube.com/watch?v=jNQXAC9IVRw'


async def mcp_check(base, key):
    import httpx2
    from mcp.client.streamable_http import streamable_http_client
    from mcp.client.session import ClientSession
    async with httpx2.AsyncClient(headers={'Authorization':'Bearer '+key},timeout=100) as http:
        async with streamable_http_client(base+'/mcp',http_client=http) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                tools=await session.list_tools()
                print('MCP tools:',[t.name for t in tools.tools],flush=True)
                result=await session.call_tool('extract_media',{'url':CAROUSEL})
                assert not result.is_error, result
                print('MCP extract_media invocation: OK',flush=True)


def main():
    # Find a free loopback port; the server must bind successfully or the test fails.
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    key=secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix='media-mcp-smoke-') as directory:
        env={**os.environ,'MEDIA_MCP_API_KEY':key,'MEDIA_MCP_PORT':str(port),
             'MEDIA_MCP_HOST':'127.0.0.1','MEDIA_MCP_PUBLIC_BASE_URL':base,'MEDIA_MCP_TEMP_DIR':directory}
        with open(Path(directory)/'server.log','w') as logs:
            process=subprocess.Popen([sys.executable,'-m','media_mcp.server'],env=env,stdout=logs,stderr=logs)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('Smoke server exited during startup')
                    try:
                        with urlopen(base+'/health',timeout=1) as response:
                            assert json.load(response)['status']=='ok'
                        break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError('Smoke server startup timed out')

                def post(path,url):
                    request=Request(base+path,data=json.dumps({'url':url}).encode(),headers={
                        'Content-Type':'application/json','Authorization':'Bearer '+key})
                    with urlopen(request,timeout=100) as response:
                        return json.load(response)

                youtube=post('/extract',YOUTUBE)
                assert youtube['platform']=='youtube' and youtube['media']
                print('YouTube metadata: OK, streams',len(youtube['media']),flush=True)
                for label,url,count in [('carousel',CAROUSEL,18),('reel',REEL,None)]:
                    data=post('/prepare',url)
                    if count: assert len(data['media'])==count
                    total=0
                    for item in data['media']:
                        with urlopen(item['url'],timeout=30) as response:
                            assert response.headers['Content-Type']==item['content_type']
                            received=0
                            while chunk:=response.read(65536): received+=len(chunk)
                            assert received==item['bytes'];total+=received
                        with urlopen(Request(item['url'],method='HEAD'),timeout=10) as response:
                            assert int(response.headers['Content-Length'])==item['bytes']
                    print(f'HTTP prepare/GET/HEAD {label}: {len(data["media"])} items, {total} bytes',flush=True)
                asyncio.run(mcp_check(base,key))
            finally:
                process.terminate()
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait()
            assert not list((Path(directory)/'sessions-v1').glob('job-*'))
            print('Shutdown temporary cleanup: OK',flush=True)


if __name__=='__main__': main()
