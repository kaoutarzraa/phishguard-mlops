import os

import pytest
from fastapi.testclient import TestClient

from phishguard.train import train_and_save


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    model_dir = tmp_path_factory.mktemp("models")
    train_and_save(model_dir, n=1500)
    os.environ["MODEL_DIR"] = str(model_dir)
    from phishguard.app import app
    with TestClient(app) as c:
        yield c


def test_health_and_ready(client):
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200


def test_phishing_scores_higher_than_legit(client):
    bad_url = "http://192.168.4.7/verify/account/12345?id=9&token=%12"
    good_url = "https://www.github.com/about"
    bad = client.post("/predict", json={"url": bad_url}).json()
    good = client.post("/predict", json={"url": good_url}).json()
    assert bad["phishing_score"] > good["phishing_score"]
    assert bad["label"] == "phishing"


def test_validation_error(client):
    assert client.post("/predict", json={}).status_code == 422


def test_metrics_exposed(client):
    client.post("/predict", json={"url": "https://example.org"})
    body = client.get("/metrics").text
    assert "model_predictions_total" in body
    assert "http_request_duration_seconds" in body
