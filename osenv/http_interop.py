"""Standard HTTP client and actual-response truncation fault acceptance."""

import argparse
import hashlib
import http.client
import json
import socket
import threading
import time
from pathlib import Path
from .worker import start
from .core import get_run
from .__main__ import call
from .web_stress import dhcp_ack_seen


def test(image, symbols):
    if not __debug__:
        raise RuntimeError("Acceptance requires Python assertions enabled")
    rid = start(
        timeout=45,
        manual=True,
        image=image,
        symbols=symbols,
        mode="long64",
        memory=64,
        network="isolated",
        timing="realtime",
    )["run_id"]
    run = get_run(rid)
    result = {"ok": False, "run_id": rid}
    try:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        assert call(rid, {"operation": "network-forward", "host_port": port})["ok"]
        deadline = time.monotonic() + 15
        while not dhcp_ack_seen(run / "network.pcap"):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read()
        assert response.status == 200 and response.reason == ""
        assert response.headers.get_content_type() == "text/html"
        assert response.headers.get_content_charset() == "utf-8"
        assert int(response.getheader("Content-Length")) == len(body)
        assert body.startswith(b"<!doctype html>") and body.endswith(b"</html>")
        connection.close()
        errors = []
        captured = []
        with socket.socket() as proxy:
            proxy.bind(("127.0.0.1", 0))
            proxy.listen(1)
            proxy.settimeout(5)
            proxy_port = proxy.getsockname()[1]

            def truncate():
                try:
                    with proxy.accept()[0] as client:
                        client.settimeout(5)
                        request = bytearray()
                        while b"\r\n\r\n" not in request:
                            data = client.recv(1024)
                            if not data or len(request) + len(data) > 768:
                                raise ValueError("Invalid proxy request")
                            request.extend(data)
                        with socket.create_connection(
                            ("127.0.0.1", port), timeout=5
                        ) as origin:
                            origin.sendall(request)
                            raw = bytearray()
                            while True:
                                data = origin.recv(4096)
                                if not data:
                                    break
                                raw.extend(data)
                                assert len(raw) <= 4096
                        assert raw.split(b"\r\n\r\n", 1)[1] == body
                        captured.append(bytes(raw))
                        (run / "truncation-origin.bin").write_bytes(raw)
                        client.sendall(
                            raw[:-1]
                        )  # Actual network fault, one body byte lost.
                except Exception as error:
                    errors.append(str(error) or type(error).__name__)

            thread = threading.Thread(target=truncate)
            thread.start()
            connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
            connection.request("GET", "/")
            response = connection.getresponse()
            try:
                response.read()
                raise AssertionError("Truncated actual response accepted as complete")
            except http.client.IncompleteRead as error:
                assert error.expected == 1 and error.partial == body[:-1]
            finally:
                connection.close()
                thread.join(7)
            assert not thread.is_alive() and not errors and captured, errors
        result = {
            "ok": True,
            "run_id": rid,
            "standard_client": True,
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "actual_response_truncation_rejected": True,
        }
    except Exception as error:
        result["error"] = str(error) or type(error).__name__
    finally:
        if not result["ok"]:
            result["capture"] = call(rid, {"operation": "capture", "mode": "long64"})
        call(rid, {"operation": "stop"})
        (run / "http-interop-verdict.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--symbols", required=True)
    result = test(**vars(parser.parse_args()))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
