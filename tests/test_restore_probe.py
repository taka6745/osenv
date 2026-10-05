import http.client
import io
import unittest
from osenv.restore_probe import validate_body, probe


class RestoreProbeTests(unittest.TestCase):
    def response(self, body, length=None, status=200):
        raw = (
            f"HTTP/1.0 {status} OK\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body) if length is None else length}\r\n\r\n"
        ).encode() + body

        class Socket:
            def makefile(self, mode):
                return io.BytesIO(raw)

        response = http.client.HTTPResponse(Socket())
        response.begin()
        return response

    def test_exact_response_and_changed_content(self):
        body = b"<html>hello</html>"
        validate_body(self.response(body), body, body)
        with self.assertRaises(ValueError):
            validate_body(self.response(body), body, b"<html>different</html>")

    def test_incomplete_and_unsuccessful_responses(self):
        body = b"<html>hello</html>"
        for response in [
            self.response(body, len(body) + 1),
            self.response(body, status=500),
        ]:
            with self.assertRaises(ValueError):
                validate_body(response, body)
        with self.assertRaises(ValueError):
            validate_body(self.response(body[:-1]), body[:-1])

    def test_repeat_rejected_before_launch(self):
        for value in [0, 21, True]:
            with self.assertRaises(ValueError):
                probe("unused", "unused", value)
