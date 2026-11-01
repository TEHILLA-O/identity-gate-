import os

os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["WORKER_ENABLED"] = "false"
os.environ["SESSION_SECRET"] = "test-session-secret"
os.environ["COOKIE_SECURE"] = "false"
