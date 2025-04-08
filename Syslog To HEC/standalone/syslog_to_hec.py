import os
import io
import re
import sys
import time
import json
import gzip
import socket
import select
import getpass
import argparse
import datetime
import requests
import functools
import threading
import traceback
import threading
import urllib.parse
from asyncio import IncompleteReadError
from socketserver import BaseServer, BaseRequestHandler, ThreadingTCPServer, ThreadingUDPServer
from requests.packages.urllib3.exceptions import InsecureRequestWarning


DEFAULT_SOCKET_TIMEOUT = 30
DEFAULT_LOG_FLUSH_INTERVAL = 10
HEC_UPLOAD_SIZE_THRESHOLD = 1 * 1024 * 1024


class Settings:
    def __get_pass(
        self,
        prompt: str,
    ) -> str:
        if os.name == 'nt' and sys.stdin is sys.__stdin__:
            import msvcrt

            for c in prompt:
                msvcrt.putwch(c)
            pw = ''
            while 1:
                c = msvcrt.getwch()
                if c == '\r' or c == '\n':
                    break
                elif c == '\003':
                    raise KeyboardInterrupt
                elif c == '\b':
                    if pw:
                        pw = pw[:-1]
                        msvcrt.putwch('\b')
                        msvcrt.putwch(' ')
                        msvcrt.putwch('\b')
                else:
                    pw = pw + c
                    msvcrt.putwch('*')

            msvcrt.putwch('\r')
            msvcrt.putwch('\n')
            return pw
        else:
            return getpass.getpass(prompt)

    def __init__(
        self,
    ) -> None:
        ap = argparse.ArgumentParser()
        ap.add_argument(
            '--syslog_protocol',
            type=str,
            choices=['udp', 'tcp'],
            default='udp',
            help='The protocol to receive syslog messages. Choose "udp" or "tcp". The default is "udp".'
        )
        ap.add_argument(
            '--syslog_port',
            type=int,
            default=514,
            help='The port number to receive syslog messages. The default is port 514.'
        )
        ap.add_argument(
            '--hec_api_url',
            type=str,
            required=True,
            help='The URL of the HTTP Event Collector (HEC) API. This option is required.'
        )
        ap.add_argument(
            '--hec_api_key_raw',
            type=str,
            default='',
            help='The API key for sending raw logs to the HTTP Event Collector (HEC).'
        )
        ap.add_argument(
            '--hec_api_key_cef',
            type=str,
            default='',
            help='The API key for sending CEF logs to the HTTP Event Collector (HEC).'
        )
        ap.add_argument(
            '--hec_compression',
            action='store_true',
            help='Enables compression for HEC messages.'
        )
        ap.add_argument(
            '--insecure',
            action='store_true',
            help='Disables SSL/TLS certificate verification.'
        )
        ap.add_argument(
            '--proxy',
            type=str,
            default='',
            help='Specifies the proxy server in the format "ip:port".'
        )
        ap.add_argument(
            '--ignore_non_syslog_message',
            action='store_true',
            help='Ignores non-syslog messages.'
        )
        ap.add_argument(
            '--new_syslog_header',
            type=str,
            choices=['RFC3164', 'RFC5424'],
            default='',
            help='Specifies the syslog header format to be used when forwarding received syslog messages.'
        )
        ap.add_argument(
            '--print_logs',
            action='store_true',
            help='Enable printing of log messages queued.'
        )
        ap.add_argument(
            '--args_stdin',
            action='store_true',
            help='Read the argument parameters specified in JSON array format from stdin.'
        )
        args = ap.parse_args()

        if args.args_stdin:
            args_stdin = json.loads(sys.stdin.read())
            if not isinstance(args_stdin, list):
                raise ValueError('The argument parameters given in stdin must be array.')
            
            args = ap.parse_args(args=sys.argv + args_stdin)

        self.__syslog_protocol = args.syslog_protocol
        self.__syslog_port = args.syslog_port
        self.__hec_api_url = args.hec_api_url
        if args.hec_api_key_raw == '*':
            self.__hec_api_key_raw = self.__get_pass('API key for RAW logs: ') or None
        else:
            self.__hec_api_key_raw = args.hec_api_key_raw or None

        if args.hec_api_key_cef == '*':
            self.__hec_api_key_cef = self.__get_pass('API key for CEF logs: ') or None
        else:
            self.__hec_api_key_cef = args.hec_api_key_cef or None

        self.__hec_compression = args.hec_compression
        self.__insecure = args.insecure
        self.__ignore_non_syslog_message = args.ignore_non_syslog_message
        self.__new_syslog_header = args.new_syslog_header or None
        self.__print_logs = args.print_logs
        self.__socket_timeout = DEFAULT_SOCKET_TIMEOUT

        if args.proxy:
            host, sep, port = args.proxy.partition(':')
            if not host or sep != ':':
                raise ValueError(f'Invalid proxy address - {args.proxy}')
            self.__proxy = f'{host}:{int(port)}'
        else:
            self.__proxy = None

    @property
    def hec_api_url(
        self
    ) -> str:
        return self.__hec_api_url

    @property
    def hec_api_key_raw(
        self
    ) -> str:
        return self.__hec_api_key_raw

    @property
    def hec_api_key_cef(
        self
    ) -> str:
        return self.__hec_api_key_cef

    @property
    def hec_compression(
        self
    ) -> bool:
        return self.__hec_compression

    @property
    def syslog_protocol(
        self
    ) -> str:
        return self.__syslog_protocol

    @property
    def syslog_port(
        self
    ) -> int:
        return self.__syslog_port

    @property
    def insecure(
        self
    ) -> bool:
        return self.__insecure

    @property
    def proxy(
        self
    ) -> str | None:
        return self.__proxy

    @property
    def socket_timeout(
        self
    ) -> int:
        return self.__socket_timeout

    @property
    def ignore_non_syslog_message(
        self
    ) -> bool:
        return self.__ignore_non_syslog_message

    @property
    def new_syslog_header(
        self
    ) -> str | None:
        return self.__new_syslog_header

    @property
    def print_logs(
        self
    ) -> bool:
        return self.__print_logs


class RestApiClient:
    def __init__(
        self,
        base_url: str,
        userid: str | None = None,
        passwd: str | None = None,
        timeout: int | None = DEFAULT_SOCKET_TIMEOUT,
        insecure: bool = False,
        proxy: str | None = None,
        nretry: int = 0,
        ok_codes: tuple[int] | None = None,
    ):
        """Initialize this instance.

        :param base_url: The base URL of the API endpoint.
        :param userid: The User ID to be used for Basic Authentication.
        :param passwd: The password to be used for Basic Authentication.
        :param timeout: The connection and read/write timeout in seconds.
        :param insecure: Set to True if the server certificate should not be verified; otherwise, False.
        :param proxy: A proxy in the format host:port.
        :param nretry: The number of connection and I/O retries.
        :param ok_codes: The HTTP status codes to consider as successful (e.g., 200, 201, 204).
        """
        self.__base_url = base_url
        self.__userid = userid
        self.__passwd = passwd
        self.__ctimeout = DEFAULT_SOCKET_TIMEOUT if timeout < DEFAULT_SOCKET_TIMEOUT else timeout
        self.__ntimeout = timeout
        self.__insecure = insecure
        self.__proxy = proxy
        self.__nretry = nretry
        self.__ok_codes = ok_codes or (requests.codes.ok,)

    def request(
        self,
        url_suffix: str,
        method: str,
        headers: dict[str, str] | None = None,
        query: str | None = None,
        body: str | bytes | None = None,
        ok_codes: tuple[int] = None,
        calmly: bool = False
    ) -> requests.Response:
        """HTTP Request

        :param url_suffix: The URL suffix for the request.
        :param method: The HTTP method to be used (e.g., GET, POST, PUT, DELETE).
        :param headers: The headers to include in the request.
        :param query: The query parameters to include in the request.
        :param body: The body of the request (for methods like POST or PUT).
        :param ok_codes: The HTTP status codes to accept as successful (e.g., 200, 201, 204).
        :param calmly: Set to True to prevent raising an exception for non-ok status codes; otherwise, False.
        :return: The HTTP response object.
        """
        url = urllib.parse.urljoin(self.__base_url, url_suffix)
        if query:
            url += '?' + urllib.parse.urlencode(query or {})

        ok_codes = ok_codes or self.__ok_codes

        sess = requests.Session()
        if self.__nretry > 0:
            sess.mount('http://', requests.adapters.HTTPAdapter(max_retries=self.__nretry))
            sess.mount('https://', requests.adapters.HTTPAdapter(max_retries=self.__nretry))

        auth = HTTPBasicAuth(
            self.__userid,
            self.__passwd
        ) if (
            self.__userid is not None and self.__passwd is not None
        ) else (
            None
        )
        proxies = {
            'http': f'http://{self.__proxy}',
            'https': f'https://{self.__proxy}',
        } if self.__proxy else None

        r = sess.request(
            method = method.upper(),
            url = url,
            headers = headers,
            data = body,
            proxies = proxies,
            verify = not self.__insecure,
            timeout = (self.__ctimeout,self.__ntimeout)
        )
        if r.status_code not in ok_codes and not calmly:
            return r.raise_for_status()
        return r


class LogSender:
    """ Log sender for Cortex HTTP Event Collector
    """
    class BufferredSender:
        """ Buffered Log sender for Cortex HTTP Event Collector
        """
        def __init__(
            self,
            client: RestApiClient,
            api_key: str,
            compression: bool,
        ) -> None:
            """Initialize the instance.

            :param settings: The settings to configure the instance.
            :param client: The basic HTTP client for the Cortex HTTP Event Collector.
            :param api_key: The API key for authenticating with the Cortex HTTP Event Collector.
            :param compression: Set to True to enable gzip compression for logs; otherwise, False.
            """
            self.__client = client
            self.__api_key = api_key
            self.__compression = compression
            self.__buffer = io.BytesIO()
            self.__buffered_nlogs = 0
            if compression:
                self.__log_writer = gzip.GzipFile(mode='wb', fileobj=self.__buffer)
                self.__content_type = 'application/gzip'
            else:
                self.__log_writer = self.__buffer
                self.__content_type = 'text/plain'

        def send_log(
            self,
            log: str,
        ) -> int:
            """Send an event log.

            :param log: The event log to be sent.
            :return: The number of log entries successfully flushed.
            """
            self.__log_writer.write((log + '\n').encode())
            self.__buffered_nlogs += 1

            if self.__buffer.getbuffer().nbytes > HEC_UPLOAD_SIZE_THRESHOLD:
                return self.flush()
            else:
                return 0

        def flush(
            self
        ) -> int:
            """Finish writing logs

            :return: The number of log entries successfully flushed.
            """
            if not self.__buffered_nlogs:
                return 0

            if self.__compression:
                self.__log_writer.close()

            # Flush the cache
            data = self.__buffer.getvalue()
            _ = self.__client.request(
                url_suffix='/logs/v1/event',
                method='POST',
                headers={
                    'Authorization': self.__api_key,
                    'Content-Type': self.__content_type,
                },
                body=data
            )
            nlogs = self.__buffered_nlogs
            print(f'* {nlogs} logs have been sent to HEC.')

            # Re-initialize the cache
            self.__buffer = io.BytesIO()
            self.__buffered_nlogs = 0
            if self.__compression:
                self.__log_writer = gzip.GzipFile(mode='wb', fileobj=self.__buffer)
            else:
                self.__log_writer = self.__buffer

            return nlogs

    def __init__(
        self,
        client: RestApiClient,
        api_key: str,
        compression: bool
    ) -> None:
        """ Initialize the instance

        :param settings: The instance settings.
        :param client: The basic HTTP client for Cortex HTTP Event Collector
        :param api_key: An API Key for Cortex HTTP Event Collector
        :param compression: Set to True to compress logs by gzip, otherwise False.
        """
        self.__sender = LogSender.BufferredSender(
            client=client,
            api_key=api_key,
            compression=compression
        )
        self.__lock = threading.Lock()
        self.__cond = threading.Condition(self.__lock)
        self.__done = False
        self.__flusher = threading.Thread(
            target=self.__periodic_flush,
            args=(),
            daemon=False
        )
        self.__flusher.start()

    def __periodic_flush(
        self
    ) -> None:
        """Flush the send buffer at intervals
        """
        timeout = DEFAULT_LOG_FLUSH_INTERVAL
        with self.__lock:
            while not self.__cond.wait_for(
                lambda: self.__done,
                timeout=timeout
            ):
                self.__sender.flush()

    def send_log(
        self,
        log: str,
    ) -> int:
        """Send an event log.

        :param log: The event log to be sent.
        :return: The number of log entries that were successfully flushed.
        """
        with self.__lock:
            return self.__sender.send_log(log)

    def flush(
        self
    ) -> int:
        """Flush the pending logs to be sent.

        :return: The number of log entries that were flushed.
        """
        with self.__lock:
            return self.__sender.flush()

    def finish(
        self
    ) -> None:
        """Complete the process of sending logs.
        """
        done = False
        with self.__lock:
            if not done:
                done = self.__done = True
                self.__cond.notify()

        if done:
            self.__flusher.join()
            self.__sender.flush()


class LogForwarder:
    """ Log Forwarder
    """
    def __init__(
        self,
        settings: Settings,
    ) -> None:
        self.__settings = settings
        if settings.hec_api_key_raw:
            self.__hec_raw = LogSender(
                client=RestApiClient(
                    base_url=settings.hec_api_url,
                    insecure=settings.insecure,
                    proxy=settings.proxy
                ),
                api_key=settings.hec_api_key_raw,
                compression=settings.hec_compression
            )
        else:
            self.__hec_raw = None

        if settings.hec_api_key_cef:
            self.__hec_cef = LogSender(
                client=RestApiClient(
                    base_url=settings.hec_api_url,
                    insecure=settings.insecure,
                    proxy=settings.proxy
                ),
                api_key=settings.hec_api_key_cef,
                compression=settings.hec_compression
            )
        else:
            self.__hec_cef = None

        self.__syslog_pattern = re.compile(
            (
                r'^(?:<(?P<pri>\d{1,3})>)(?:(:?(?P<datetime_3164>(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec))'
                r' +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})) (?P<host_3164>\S+)'
                r' (?:(?P<tag>[^:\[]{1,32})(?:\[(?P<pid>\d*)\])?: )?(?P<msg_3164>.*)'
                r'|'
                r'(?P<version>\d{1,2})'
                r' (?:-|(?P<datetime_5424>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})))'
                r' (?:-|(?P<host_5424>\S{1,255})) (?:-|(?P<app>\S{1,48})) (?:-|(?P<proc_id>\S{1,128}))'
                r' (?:-|(?P<msg_id>\S{1,32})) (?:-|(?P<structured_data>\[(?:[^ =\]]+)'
                r' (?:(?:[^\]\\]|\\.)*)\]))(?: (?P<msg_5424>.*))?)'
            )
        )

    def send_log(
        self,
        log: str,
    ) -> None:
        """Send a log message.

        :param log: The log message to be sent.
        """
        syslog_message = None
        if (
            self.__settings.ignore_non_syslog_message or
            (self.__settings.new_syslog_header or '') in ('RFC3164', 'RFC5424') or
            self.__hec_cef
        ):
            if syslog_params := self.__syslog_pattern.match(log):
                syslog_message = syslog_params.group('msg_3164') or syslog_params.group('msg_5424') or ''
            elif self.__settings.ignore_non_syslog_message:
                return

        if (self.__settings.new_syslog_header or '') in ('RFC3164', 'RFC5424'):
            t = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
            pri = syslog_params.group('pri') or '0'
            host = syslog_params.group('host_3164') or syslog_params.group('host_5424') or socket.gethostname()
            msg = log if syslog_message is None else syslog_message
            if self.__settings.new_syslog_header == 'RFC3164':
                log = f'<{pri}>{t.strftime("%b %d %H:%M:%S")} {host} {msg}'
            else:
                app = syslog_params.group('tag') or syslog_params.group('app') or '-'
                proc_id = syslog_params.group('pid') or syslog_params.group('proc_id') or '-'
                msg_id = syslog_params.group('msg_id') or '-'
                structured_data = syslog_params.group('structured_data') or '-'
                log = f'<{pri}>1 {t.strftime("%Y-%m-%dT%H:%M:%SZ")} {host} {app} {proc_id} {msg_id} {structured_data} {msg}'

        if self.__hec_cef and (syslog_message or '').startswith('CEF:'):
            self.__hec_cef.send_log(log)
            if self.__settings.print_logs:
                print(f'[CEF] {log}')
            return

        if self.__hec_raw:
            self.__hec_raw.send_log(log)
            if self.__settings.print_logs:
                print(f'[RAW] {log}')

    def flush(
        self,
    ) -> None:
        """Flush log messages in the cache
        """
        if self.__hec_raw:
            self.__hec_raw.flush()
        if self.__hec_cef:
            self.__hec_cef.flush()

    def finish(
        self,
    ) -> None:
        if self.__hec_raw:
            self.__hec_raw.finish()
        if self.__hec_cef:
            self.__hec_cef.finish()


class UdpLogForwardingHandler(BaseRequestHandler):
    """ Log Forwarding Handler (UDP)
    """
    def __init__(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
        server: BaseServer,
    ) -> None:
        """Initialize this instance.

        :param request: The new socket object to be used to communicate with the client.
        :param client_address: Client address returned by BaseServer.get_request().
        :param server: BaseServer object used for handling the request.
        """
        self.__log_forwarder = None
        BaseRequestHandler.__init__(self, request, client_address, server)

    def setup(
        self
    ) -> None:
        self.__log_forwarder = self.server.log_forwarder

    def handle(
        self
    ) -> None:
        log, s = self.request
        try:
            if log := log.decode(errors='ignore').rstrip('\r\n'):
                self.__log_forwarder.send_log(log)
        except Exception:
            traceback.print_exc()


class TcpLogForwardingHandler(BaseRequestHandler):
    """ Log Forwarding Handler (TCP)
    """
    def __init__(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
        server: BaseServer,
    ) -> None:
        """Initialize this instance.

        :param request: The new socket object to be used to communicate with the client.
        :param client_address: Client address returned by BaseServer.get_request().
        :param server: BaseServer object used for handling the request.
        """
        self.__log_forwarder = None
        BaseRequestHandler.__init__(self, request, client_address, server)

    def setup(
        self
    ) -> None:
        self.__log_forwarder = self.server.log_forwarder

    def handle(
        self
    ) -> None:
        try:
            ss = self.request
            while True:
                # Read payload length
                length = None
                for c in iter(functools.partial(ss.recv, 1), b''):
                    if c.isdigit():
                        length = ((length or 0) * 10) + int(c)
                    elif c == b' ' and length is not None:
                        break
                    else:
                        raise RuntimeError('Invalid syslog payload')
                else:
                    if length is None:
                        return
                    raise RuntimeError('Invalid syslog payload')

                # Read syslog payload
                log = bytearray(length)
                view = memoryview(log)
                pos = 0
                while pos < length:
                    n = ss.recv_into(view[pos:])
                    if not n:
                        raise IncompleteReadError(log, length)
                    pos += n

                if log := log.decode(errors='ignore').rstrip('\r\n'):
                    self.__log_forwarder.send_log(log)

        except Exception:
            traceback.print_exc()
        finally:
            self.request.close()
            self.__log_forwarder.flush()


def main(
) -> None:
    """
    Main
    """
    settings = Settings()
    log_forwarder = LogForwarder(settings)
    try:
        print(f'Starting the syslog_to_hec server on port {settings.syslog_port} ...')

        if settings.syslog_protocol == 'udp':
            ThreadingUDPServer.allow_reuse_address = True
            with ThreadingUDPServer(('', settings.syslog_port), UdpLogForwardingHandler) as server:
                server.timeout = settings.socket_timeout
                server.log_forwarder = log_forwarder
                server.serve_forever()

        elif settings.syslog_protocol == 'tcp':
            ThreadingTCPServer.allow_reuse_address = True
            with ThreadingTCPServer(('', settings.syslog_port), TcpLogForwardingHandler) as server:
                server.timeout = settings.socket_timeout
                server.log_forwarder = log_forwarder
                server.serve_forever()
        else:
            raise ValueError(f'Invalid syslog protocol - {settings.syslog_protocol}')
    finally:
        log_forwarder.finish()

    input('Press ENTER to exit...')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
