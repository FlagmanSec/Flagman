"""Downloads from a small web server on this machine: no internet needed."""

import hashlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from flagman_ml.datasets.download import DownloadError, check_budget, get
from flagman_ml.datasets.manifest import Entry

DATA = bytes(range(256)) * 400  # 102,400 bytes
DIGEST = hashlib.sha256(DATA).hexdigest()
SIZE = len(DATA)


class Server:
    """Serves DATA at /file; honours Range requests unless told not to."""

    def __init__(self, ranges=True):
        self.ranges, self.requests = ranges, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append(self.headers.get("Range"))
                start = 0
                if outer.ranges and self.headers.get("Range"):
                    start = int(self.headers["Range"].removeprefix("bytes=").rstrip("-"))
                    if start >= len(DATA):
                        self.send_response(416)
                        self.end_headers()
                        return
                    self.send_response(206)
                else:
                    self.send_response(200)
                self.send_header("Content-Length", str(len(DATA) - start))
                self.end_headers()
                self.wfile.write(DATA[start:])

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/file"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = Server()
    yield s
    s.close()


def entry(url, sha256=DIGEST, size=SIZE):
    return Entry(name="day1/flows.pcap", url=url, listed_size="100K", bytes=size,
                 sha256=sha256, kind="pcap")


def test_a_file_is_downloaded_and_checked(tmp_path, server):
    outcome = get(entry(server.url), tmp_path)
    assert outcome.status == "downloaded"
    assert (tmp_path / "day1/flows.pcap").read_bytes() == DATA
    assert not (tmp_path / "day1/flows.pcap.part").exists()


def test_a_broken_download_resumes_where_it_stopped(tmp_path, server):
    (tmp_path / "day1").mkdir()
    (tmp_path / "day1/flows.pcap.part").write_bytes(DATA[:40_000])  # as if cut off
    assert get(entry(server.url), tmp_path).status == "downloaded"
    assert server.requests == ["bytes=40000-"]
    assert (tmp_path / "day1/flows.pcap").read_bytes() == DATA


def test_a_server_without_ranges_sends_everything_again(tmp_path):
    server = Server(ranges=False)
    try:
        (tmp_path / "day1").mkdir()
        (tmp_path / "day1/flows.pcap.part").write_bytes(b"junk" * 100)
        get(entry(server.url), tmp_path)
        assert (tmp_path / "day1/flows.pcap").read_bytes() == DATA
    finally:
        server.close()


def test_a_wrong_checksum_never_gets_the_final_name(tmp_path, server):
    with pytest.raises(DownloadError, match="SHA-256 differs"):
        get(entry(server.url, sha256="0" * 64), tmp_path)
    assert not (tmp_path / "day1/flows.pcap").exists()
    assert (tmp_path / "day1/flows.pcap.bad").exists()  # kept to look at


def test_without_a_checksum_nothing_is_downloaded_unless_recording(tmp_path, server):
    with pytest.raises(DownloadError, match="--record"):
        get(entry(server.url, sha256="", size=0), tmp_path)
    assert server.requests == []
    outcome = get(entry(server.url, sha256="", size=0), tmp_path, record=True)
    assert (outcome.status, outcome.bytes, outcome.sha256) == ("recorded", len(DATA), DIGEST)


def test_a_file_already_in_place_is_checked_not_downloaded(tmp_path, server):
    (tmp_path / "day1").mkdir()
    (tmp_path / "day1/flows.pcap").write_bytes(DATA)
    assert get(entry(server.url), tmp_path).status == "kept"
    assert server.requests == []


def huge(size):
    return Entry(name="huge.pcap", url="https://example.org/huge.pcap", listed_size=size,
                 bytes=0, sha256="", kind="pcap")


def test_twenty_gigabytes_or_more_need_a_clear_yes(tmp_path):
    with pytest.raises(DownloadError, match="--allow-large"):
        check_budget([huge("66G")], tmp_path, allow_large=False)
    assert check_budget([huge("5.0M")], tmp_path, allow_large=False) == 5 * 1024**2


def test_the_disk_must_hold_the_download(tmp_path):
    with pytest.raises(DownloadError, match="GB free"):
        check_budget([huge("900T")], tmp_path, allow_large=True)
