import pytest
from app.scanner import scan_sqli, scan_xss, get_form_details, run_scan
from unittest.mock import patch, MagicMock

class TestGetFormDetails:
    def test_basic_form(self):
        from bs4 import BeautifulSoup
        html = '<form action="/login" method="post"><input type="text" name="user"/></form>'
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        details = get_form_details(form)
        assert details["action"] == "/login"
        assert details["method"] == "post"
        assert len(details["inputs"]) == 1

class TestRunScan:
    def test_invalid_url(self):
        result = run_scan("not-a-url")
        assert result["error"] is not None

    def test_valid_structure(self):
        with patch("app.scanner.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.content = b"<html><body></body></html>"
            mock_resp.text = ""
            mock_get.return_value = mock_resp
            result = run_scan("http://example.com")
            assert "sqli" in result
            assert "xss" in result
            assert "summary" in result