"""Fail-closed network boundary installed ONLY in isolated extraction workers.

Python transports connect to the exact numeric IP that was validated, while
retaining the original hostname for TLS certificate checks and SNI. No proxies,
external JS engines or native curl transports are permitted in these workers.
"""
import ipaddress
import os
import socket
from urllib.parse import urlsplit

SOURCE_HOSTS = frozenset(('instagram.com', 'www.instagram.com', 'm.instagram.com',
    'i.instagram.com', 'youtube.com', 'www.youtube.com', 'm.youtube.com',
    'youtu.be', 'www.youtube-nocookie.com', 'youtubei.googleapis.com'))
CDN_DOMAINS = ('cdninstagram.com', 'fbcdn.net', 'googlevideo.com', 'ytimg.com')


def allowed_host(host, *, media_only=False):
    host = (host or '').lower()
    return (not media_only and host in SOURCE_HOSTS) or any(
        host.endswith('.' + domain) for domain in CDN_DOMAINS)


def check_url(url, *, media_only=False):
    try:
        p = urlsplit(url)
        if (p.scheme != 'https' or p.username or p.password or p.port not in (None, 443)
                or not allowed_host(p.hostname, media_only=media_only)):
            raise ValueError()
        return p.hostname
    except (ValueError, TypeError):
        raise OSError('Outbound URL is not permitted') from None


def public_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError()
        if isinstance(ip, ipaddress.IPv6Address) and (ip.ipv4_mapped or ip.sixtofour or ip.teredo
                or ip in ipaddress.ip_network('64:ff9b::/96')
                or ip in ipaddress.ip_network('64:ff9b:1::/48')):
            raise ValueError()
        return str(ip)
    except ValueError:
        raise OSError('Non-public outbound address') from None


class NetworkGuard:
    def __init__(self):
        self.resolve = socket.getaddrinfo
        self.connect = socket.socket.connect
        self.connect_ex = socket.socket.connect_ex

    def getaddrinfo(self, host, port, *args, **kwargs):
        if not isinstance(host, str) or not allowed_host(host) or port not in (443, '443'):
            raise OSError('Outbound host/port is not permitted')
        records = self.resolve(host, port, *args, **kwargs)
        if not records:
            raise OSError('No DNS addresses')
        for record in records:
            public_ip(record[4][0])
        return records

    def destination(self, sock, address):
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or not isinstance(address, tuple):
            raise OSError('Outbound socket family is not permitted')
        host, port = address[:2]
        if port != 443:
            raise OSError('Outbound port is not permitted')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return self.getaddrinfo(host, port, sock.family, socket.SOCK_STREAM)[0][4]
        public_ip(host)
        return address  # numeric IP: connect performs no second DNS resolution

    def install(self):
        guard = self
        socket.getaddrinfo = self.getaddrinfo
        socket.socket.connect = lambda sock, addr: guard.connect(sock, guard.destination(sock, addr))
        socket.socket.connect_ex = lambda sock, addr: guard.connect_ex(sock, guard.destination(sock, addr))
        for name in tuple(os.environ):
            if name.lower().endswith('_proxy'):
                os.environ.pop(name, None)
        os.environ['NO_PROXY'] = '*'
        from yt_dlp import YoutubeDL
        original_init = YoutubeDL.__init__
        original_open = YoutubeDL.urlopen

        def initialize(client, params=None, *args, **kwargs):
            params = dict(params or {})
            params.update(proxy='', js_runtimes={}, remote_components=[], cachedir=False)
            original_init(client, params, *args, **kwargs)
            # Force the Python socket path we can pin and validate. Do not let
            # optional future curl_cffi installs bypass this boundary.
            for key in list(client._request_director.handlers):
                if key != 'Urllib':
                    client._request_director.handlers.pop(key).close()

        def urlopen(client, request):
            check_url(request if isinstance(request, str) else request.url)
            return original_open(client, request)

        YoutubeDL.__init__ = initialize
        YoutubeDL.urlopen = urlopen
        # Every urllib redirect, including yt-dlp's redirect subclass, goes
        # through OpenerDirector.open before any destination is connected.
        import urllib.request
        original_urllib_open = urllib.request.OpenerDirector.open

        def urllib_open(opener, fullurl, *args, **kwargs):
            check_url(fullurl if isinstance(fullurl, str) else fullurl.full_url)
            return original_urllib_open(opener, fullurl, *args, **kwargs)

        urllib.request.OpenerDirector.open = urllib_open
