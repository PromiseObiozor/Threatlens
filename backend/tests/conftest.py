import os


# Keep backend tests isolated from the developer's local ThreatLens database.
os.environ.setdefault("THREATLENS_DATABASE_URL", "sqlite:///:memory:")
