from backend.main import app


def test_backend_app_imports_as_package():
    assert app is not None
