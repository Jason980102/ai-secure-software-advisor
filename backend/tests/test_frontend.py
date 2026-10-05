from fastapi.testclient import TestClient
from app.main import app

def test_home_and_assets():
    client=TestClient(app)
    response=client.get('/')
    assert response.status_code==200
    assert 'text/html' in response.headers['content-type']
    assert 'id="scan-form"' in response.text
    for asset in ['app.js','style.css']:
        assert client.get('/assets/'+asset).status_code==200
    assert client.get('/assets/../.env').status_code!=200
    assert client.get('/health').status_code==200
