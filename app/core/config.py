from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # API Keys
    SHODAN_API_KEY: str | None = Field(default=None, repr=False)
    CENSYS_API_ID: str | None = Field(default=None, repr=False)
    CENSYS_API_SECRET: str | None = Field(default=None, repr=False)
    DEHASHED_API_KEY: str | None = Field(default=None, repr=False)
    DEHASHED_EMAIL: str | None = None

    # Execution settings
    DEFAULT_TIMEOUT: int = Field(default=60, ge=1)
    PROCESS_TERMINATION_GRACE_SECONDS: float = Field(default=2.0, gt=0)
    HTTP_MAX_ATTEMPTS: int = Field(default=3, ge=1)
    HTTP_BACKOFF_SECONDS: float = Field(default=1.0, ge=0)
    MAX_CONCURRENT_TASKS: int = Field(default=10, ge=1, le=100)
    MAX_BATCH_SIZE: int = Field(default=25, ge=1, le=25)
    MAX_ADAPTERS_PER_SCAN: int = Field(default=25, ge=1, le=50)
    MAX_QUEUE_DEPTH: int = Field(default=100, ge=1)
    MAX_OUTSTANDING_SCANS_PER_PRINCIPAL: int = Field(default=10, ge=1)
    MAX_REQUEST_BODY_BYTES: int = Field(default=65_536, ge=1, le=1_048_576)
    WORKER_MAX_TRIES: int = Field(default=3, ge=1, le=10)
    WORKER_JOB_TIMEOUT_SECONDS: int = Field(default=3600, ge=60)
    WORKER_HEALTH_INTERVAL_SECONDS: int = Field(default=10, ge=2, le=60)
    WORKER_LEASE_HEARTBEAT_SECONDS: float = Field(default=10, ge=1, le=60)
    RUNNING_SCAN_LEASE_SECONDS: float = Field(default=60, ge=5, le=3600)
    DISPATCH_SWEEP_SECONDS: float = Field(default=2.0, gt=0, le=60)

    # Redis for ARQ
    REDIS_HOST: str = Field(default="localhost", min_length=1)
    REDIS_PORT: int = Field(default=6379, ge=1, le=65535)
    REDIS_DATABASE: int = Field(default=0, ge=0)
    REDIS_USERNAME: str | None = None
    REDIS_PASSWORD: str | None = Field(default=None, repr=False)
    REDIS_SSL: bool = False

    # Neo4j graph persistence
    NEO4J_URI: str = Field(default="bolt://localhost:7687", min_length=1)
    NEO4J_USER: str = Field(default="neo4j", min_length=1)
    NEO4J_PASSWORD: str | None = Field(default=None, repr=False)
    NEO4J_DATABASE: str = Field(default="neo4j", min_length=1)

    # HTTP API policy controls consumed by later stabilization tasks
    CORS_ORIGINS: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    )
    AUTH_ENABLED: bool = True
    OIDC_ISSUER: str | None = None
    OIDC_AUDIENCE: str | None = None
    OIDC_JWKS_URL: str | None = None
    OIDC_ALGORITHMS: list[str] = Field(default_factory=lambda: ["RS256"])
    OIDC_LEEWAY_SECONDS: int = Field(default=30, ge=0, le=300)
    OIDC_JWKS_TIMEOUT_SECONDS: float = Field(default=5, gt=0, le=30)
    OIDC_JWKS_CACHE_SECONDS: int = Field(default=300, ge=60)
    OIDC_ROLES_CLAIM: str = "roles"
    OIDC_ADMIN_ROLE: str = "recon-admin"
    LOCAL_PRINCIPAL_SUB: str = "local-development"
    MAX_AUTHORIZATION_HEADER_BYTES: int = Field(default=8192, ge=256, le=65_536)
    OPERATIONS_TOKEN: str | None = Field(default=None, repr=False)
    ENABLE_API_DOCS: bool = False
    ALLOW_ACTIVE_SCANNING: bool = False
    ACTIVE_TARGET_ALLOWLIST: list[str] = Field(default_factory=list)
    RATE_LIMIT_REQUESTS: int = Field(default=120, ge=1)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, ge=1)
    SCAN_EVENT_POLL_SECONDS: float = Field(default=0.5, ge=0.1, le=10)
    SCAN_EVENT_MAX_SECONDS: int = Field(default=300, ge=10, le=3600)
    SCAN_EVENT_MAX_CONNECTIONS_PER_PRINCIPAL: int = Field(default=3, ge=1, le=20)
    DATA_RETENTION_DAYS: int = Field(default=90, ge=1)
    RETENTION_SWEEP_SECONDS: int = Field(default=3600, ge=60)
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str | None = None

    @field_validator("CORS_ORIGINS")
    @classmethod
    def reject_wildcard_cors(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError("credentialed CORS origins must not contain '*'")
        return value

    @field_validator("OIDC_ALGORITHMS")
    @classmethod
    def validate_oidc_algorithms(cls, value: list[str]) -> list[str]:
        cleaned = [algorithm.strip() for algorithm in value if algorithm.strip()]
        asymmetric = {
            "RS256", "RS384", "RS512",
            "PS256", "PS384", "PS512",
            "ES256", "ES384", "ES512",
            "EdDSA",
        }
        if not cleaned or any(algorithm not in asymmetric for algorithm in cleaned):
            raise ValueError(
                "OIDC_ALGORITHMS must be a non-empty asymmetric allow-list"
            )
        return cleaned

    @model_validator(mode="after")
    def validate_worker_lease(self) -> "Settings":
        if self.RUNNING_SCAN_LEASE_SECONDS <= self.WORKER_LEASE_HEARTBEAT_SECONDS:
            raise ValueError(
                "RUNNING_SCAN_LEASE_SECONDS must be greater than "
                "WORKER_LEASE_HEARTBEAT_SECONDS"
            )
        return self

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
