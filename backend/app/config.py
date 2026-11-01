from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://identitygate:identitygate@localhost:5432/identitygate"
    keycloak_internal_url: str = "http://localhost:8080"
    keycloak_public_url: str = "http://localhost:8080"
    keycloak_realm: str = "northstar"
    oidc_client_id: str = "identitygate"
    oidc_client_secret: str = ""
    oidc_audience: str = "identitygate-api"
    scim_client_id: str = "identitygate-provisioner"
    scim_client_secret: str = ""
    scim_audience: str = "http://localhost:8080/realms/northstar/scim/v2"
    kc_admin_username: str = ""
    kc_admin_password: str = ""
    finance_client_secret: str = ""
    projects_client_secret: str = ""
    downstream_scim_url: str = "http://localhost:8103/scim/v2"
    downstream_scim_token: str = ""
    finance_internal_url: str = ""
    public_app_url: str = "http://localhost:5173"
    session_secret: str = "local-dev-session-secret"
    demo_user_password: str = ""
    cookie_secure: bool = False
    auto_expire: bool = False
    worker_enabled: bool = True
    worker_interval_seconds: int = 15
    data_dir: str = ""
    report_dir: str = ""
    environment_name: str = "local"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def issuer(self) -> str:
        return f"{self.keycloak_public_url.rstrip('/')}/realms/{self.keycloak_realm}"

    @property
    def internal_realm(self) -> str:
        return f"{self.keycloak_internal_url.rstrip('/')}/realms/{self.keycloak_realm}"

    @property
    def scim_base(self) -> str:
        return f"{self.internal_realm}/scim/v2"

    @property
    def data_path(self) -> Path:
        if self.data_dir:
            return Path(self.data_dir)
        return ROOT / "data"

    @property
    def report_path(self) -> Path:
        path = Path(self.report_dir) if self.report_dir else ROOT / ".local" / "reports"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def finance_reports_url(self) -> str:
        if self.finance_internal_url:
            return self.finance_internal_url.rstrip("/") + "/api/reports"
        host = "finance" if "://" in self.keycloak_internal_url and "localhost" not in self.keycloak_internal_url else "localhost"
        return f"http://{host}:8101/api/reports"


def get_settings() -> Settings:
    return Settings()
