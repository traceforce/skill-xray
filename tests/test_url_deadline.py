"""Real HTTP buffering over an instrumented TLS transport; no network or sleeps."""

import io
import ssl
from collections import deque
from types import SimpleNamespace

import pytest

from skill_xray import resolve


@pytest.fixture
def transfer(monkeypatch):
    clock = [0.0]
    state = SimpleNamespace(now=clock, sockets=[], readers=[], contexts=[], timeouts=[])
    monkeypatch.setattr(resolve.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(resolve, "URL_DEADLINE_SECONDS", 0.05)

    def setup(parts, *, connect_delay=0, handshake_delay=0, send_delay=0,
              late_success=False):
        chunks = deque([bytearray(data), delay] for data, delay in parts)

        def wait(delay, timeout):
            state.timeouts.append(timeout)
            clock[0] += delay if late_success else min(delay, timeout)
            if delay >= timeout and not late_success:
                raise TimeoutError("simulated socket timeout")

        class RawSocket:
            def __init__(self, timeout):
                self.sim_timeout, self.closed = timeout, False

            def settimeout(self, value):
                self.sim_timeout = value

            def close(self):
                self.closed = True

        def connect(address, timeout):
            assert address == ("93.184.216.34", 443)
            wait(connect_delay, timeout)
            raw = RawSocket(timeout)
            state.sockets.append(raw)
            return raw

        def wrap(context, raw, *, server_hostname):
            assert server_hostname == "example.com"
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            state.contexts.append(context)
            wait(handshake_delay, raw.sim_timeout)

            class Wire:
                def read(self, size, buffer):
                    while chunks and not chunks[0][0]:
                        chunks.popleft()
                    if not chunks:
                        return 0
                    data, delay = chunks[0]
                    wait(delay, sock.sim_timeout)
                    count = min(size, 1 if delay else len(data))
                    buffer[:count] = data[:count]
                    del data[:count]
                    return count

                def write(self, data):
                    wait(send_delay, sock.sim_timeout)
                    return 1 if send_delay else len(data)

            class Reader(io.RawIOBase):
                def readable(self):
                    return True

                def readinto(self, buffer):
                    return sock.recv_into(buffer)

            class TLS(context.sslsocket_class):
                def __init__(self):
                    self.sim_timeout, self.closed = raw.sim_timeout, False
                    self._sslobj = Wire()

                def settimeout(self, value):
                    self.sim_timeout = value

                def makefile(self, mode):
                    assert mode == "rb"
                    reader = io.BufferedReader(Reader())
                    state.readers.append(reader)
                    return reader

                def close(self):
                    self.closed = True
                    raw.close()

            sock = TLS()
            state.sockets.append(sock)
            return sock

        monkeypatch.setattr(resolve.socket, "create_connection", connect)
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        return state

    return setup


FIXED = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n"
CHUNKED = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"


@pytest.mark.parametrize("parts", [
    [(FIXED, 0), (b"abcdefgh", 0.02)],
    [(b"HTTP/1.1 200 OK\r\n", 0.02), (b"Content-Length: 8\r\n\r\nabcdefgh", 0)],
    [(b"HTTP/1.1 200 OK\r\n", 0), (b"X-Slow: abcdefgh\r\n", 0.02),
     (b"Content-Length: 8\r\n\r\nabcdefgh", 0)],
    [(CHUNKED, 0), (b"8;extension=abcdefgh\r\n", 0.02), (b"abcdefgh\r\n0\r\n\r\n", 0)],
    [(CHUNKED + b"8\r\n", 0), (b"abcdefgh", 0.02), (b"\r\n0\r\n\r\n", 0)],
    [(CHUNKED + b"8\r\nabcdefgh\r\n0\r\n", 0), (b"X-Trailer: abcdefgh\r\n\r\n", 0.02)],
    [(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", 0), (b"abcdefgh", 0.02)],
], ids=["body", "status", "header", "chunk-size", "chunk-body", "trailer", "until-eof"])
def test_trickle_cannot_outlive_deadline(transfer, tmp_path, parts):
    state = transfer(parts)
    with pytest.raises(resolve.IngestLimitExceededError, match="deadline"):
        resolve._download_capped("example.com", 443, "/skill", "93.184.216.34", tmp_path / "out")
    assert state.now[0] <= 0.05
    assert all(sock.closed for sock in state.sockets)
    assert all(reader.closed for reader in state.readers)


@pytest.mark.parametrize("stage", ["connect", "handshake", "combined", "request"])
def test_setup_and_request_share_download_budget(transfer, tmp_path, stage):
    delays = {"connect": {"connect_delay": 0.08}, "handshake": {"handshake_delay": 0.08},
              "combined": {"connect_delay": 0.03, "handshake_delay": 0.03},
              "request": {"send_delay": 0.02}}[stage]
    state = transfer([(FIXED + b"abcdefgh", 0)], **delays)
    with pytest.raises(resolve.IngestLimitExceededError, match="deadline"):
        resolve._download_capped("example.com", 443, "/skill", "93.184.216.34", tmp_path / "out")
    assert state.now[0] <= 0.05
    assert all(sock.closed for sock in state.sockets)


@pytest.mark.parametrize("response", [FIXED + b"abcdefgh",
                                     CHUNKED + b"8\r\nabcdefgh\r\n0\r\n\r\n"])
def test_on_time_transfer_preserves_bytes_and_tls_checks(transfer, tmp_path, response):
    state = transfer([(response, 0)], connect_delay=0.005, handshake_delay=0.005)
    out = tmp_path / "out"
    resolve._download_capped("example.com", 443, "/skill", "93.184.216.34", out)
    assert out.read_bytes() == b"abcdefgh"
    assert all(sock.closed for sock in state.sockets)
    assert state.now[0] < 0.05
    assert all(timeout <= 0.05 for timeout in state.timeouts)
    assert state.timeouts == sorted(state.timeouts, reverse=True)
    assert all(reader.closed for reader in state.readers)


@pytest.mark.parametrize("stage", ["handshake", "request", "read"])
def test_successful_io_returning_after_deadline_is_not_accepted(transfer, tmp_path, stage):
    parts = [(FIXED, 0), (b"abcdefgh", 0.08 if stage == "read" else 0)]
    state = transfer(parts, late_success=True,
                     handshake_delay=0.08 if stage == "handshake" else 0,
                     send_delay=0.08 if stage == "request" else 0)
    with pytest.raises(resolve.IngestLimitExceededError, match="deadline"):
        resolve._download_capped("example.com", 443, "/skill", "93.184.216.34", tmp_path / "out")
    assert all(sock.closed for sock in state.sockets)
    assert all(reader.closed for reader in state.readers)


def test_idle_socket_timeout_is_not_mislabeled_as_whole_download_deadline(
        transfer, tmp_path, monkeypatch):
    monkeypatch.setattr(resolve, "URL_TIMEOUT_SECONDS", 0.01)
    state = transfer([(FIXED, 0), (b"abcdefgh", 0.02)])
    with pytest.raises(TimeoutError, match="socket timeout"):
        resolve._download_capped("example.com", 443, "/skill", "93.184.216.34", tmp_path / "out")
    assert state.now[0] < 0.05
    assert all(reader.closed for reader in state.readers)


def test_deadline_failure_removes_url_temporary_directory(transfer, tmp_path, monkeypatch):
    transfer([(FIXED, 0), (b"abcdefgh", 0.02)])
    monkeypatch.setattr(resolve, "_check_url_host",
                        lambda _: ("example.com", 443, "/skill", "93.184.216.34"))
    temporary = tmp_path / "download"
    temporary.mkdir()
    monkeypatch.setattr(resolve.tempfile, "mkdtemp", lambda **_: str(temporary))
    with pytest.raises(resolve.IngestLimitExceededError, match="deadline"):
        resolve._fetch_url("https://example.com/skill")
    assert not temporary.exists()
