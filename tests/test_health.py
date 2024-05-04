"""Basic smoke tests for health and home routes."""

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_endpoint() -> None:
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_home_page_renders() -> None:
    client = TestClient(create_app())
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "DeliverCheck" in response.text
    assert "Check if your email is ready to send and receive, and how to fix it." in response.text
    assert "/static/vendor/htmx.min.js" in response.text
    assert "/static/css/app.css" in response.text


def test_vendored_assets_served() -> None:
    client = TestClient(create_app())
    htmx = client.get("/static/vendor/htmx.min.js")
    assert htmx.status_code == 200
    assert "htmx" in htmx.text

    css = client.get("/static/css/app.css")
    assert css.status_code == 200
    assert "Inter" in css.text
