"""Application configuration management."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable override support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ENVIRONMENT: str = Field(default="development", description="Environment mode")
    PROVIDER_MODE: str = Field(default="mock", description="AI provider mode: 'mock' or 'groq'")
    POLICY_VERSION: str = Field(default="policy-v1", description="Active policy version identifier")
    POLICY_LOADED: bool = Field(default=True, description="Whether policy configurations are loaded")
    
    # Payload limits (per blueprint api_contracts.md)
    MAX_BODY_SIZE_BYTES: int = Field(
        default=32768, description="Maximum HTTP request body size in bytes (32 KiB)"
    )
    MAX_PROMPT_SIZE_BYTES: int = Field(
        default=10240, description="Maximum prompt text length in UTF-8 bytes (10 KiB)"
    )

    # Detector settings (Milestone 2)
    DETECTOR_VERSION: str = Field(default="detector-v1", description="Detector ruleset version")
    EMPLOYEE_ID_PATTERN: str = Field(
        default=r"\bEMP-[0-9]{4,8}\b",
        description="Regular expression pattern for employee ID detection",
    )

    # Groq Provider Settings (Milestone 7)
    GROQ_API_KEY: str = Field(
        default="", description="Secret API key for Groq Cloud (backend only)"
    )
    GROQ_MODEL: str = Field(
        default="llama-3.1-8b-instant", description="Default Groq LLM model"
    )
    GROQ_BASE_URL: str = Field(
        default="https://api.groq.com/openai/v1", description="Groq API base URL"
    )
    PROVIDER_TIMEOUT_SECONDS: float = Field(
        default=20.0, description="Provider request timeout in seconds"
    )
    PROVIDER_MAX_RETRIES: int = Field(
        default=1, description="Maximum provider retry attempts for transient errors"
    )

    # CORS & Deployment Settings
    CORS_ALLOWED_ORIGINS: list[str] = Field(
        default=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        description="Allowed CORS origins list",
    )
    CORS_ALLOWED_ORIGIN_REGEX: str | None = Field(
        default=r"^https://.*\.trycloudflare\.com$",
        description="Allowed CORS origin regex pattern (e.g. for HTTPS tunnels)",
    )

    # Shared Team Access Settings (for hackathon demo sharing)
    TEAM_ACCESS_KEY: str = Field(
        default="",
        description="Passkey required for accessing shared demonstration instance. If empty, check is disabled.",
    )

    # Enterprise Human-Review Workflow Settings
    HISTORICAL_DATABASE_PATH: str = Field(
        default="privai_data.db",
        description="Path to immutable historical baseline SQLite database",
    )
    DATABASE_PATH: str = Field(
        default="privai_dev.db",
        description="Path to active runtime SQLite database for review tickets and audit records",
    )
    JWT_SECRET_KEY: str = Field(
        default="privai-dev-jwt-secret-replace-in-production-only-32bytes",
        description="JWT HMAC signing secret for reviewer authentication",
    )
    JWT_ALGORITHM: str = Field(
        default="HS256", description="JWT signing algorithm"
    )
    JWT_ISSUER: str = Field(
        default="privai-auth", description="Trusted JWT token issuer"
    )
    JWT_AUDIENCE: str = Field(
        default="privai-api", description="Expected JWT token audience"
    )
    REVIEW_PERMIT_SECRET: str = Field(
        default="privai-dev-permit-signing-secret-key-32bytes-min",
        description="Secret key for signing single-use cryptographic review permits",
    )
    REVIEW_ENCRYPTION_KEY: str = Field(
        default="", description="Base64/Hex 32-byte key for AES-256-GCM envelope encryption at rest"
    )
    REVIEW_TICKET_TTL_HOURS: int = Field(
        default=24, description="Exact TTL in hours for pending review tickets"
    )
    REVIEW_PERMIT_TTL_SECONDS: int = Field(
        default=300, description="Exact TTL in seconds for single-use review permits"
    )

    # Enterprise KMS & Secrets Management Settings
    KMS_PROVIDER: str = Field(
        default="local", description="KMS provider: 'local', 'vault', or 'aws'"
    )
    KMS_ENDPOINT: str = Field(
        default="", description="External KMS / Vault service endpoint URL"
    )
    KMS_AUTH_TOKEN: str = Field(
        default="", description="Authentication credential for external KMS"
    )
    ACTIVE_ENCRYPTION_KEY_ID: str = Field(
        default="enc-key-v1", description="Identifier of active AES-256 encryption key in KMS"
    )
    ACTIVE_PERMIT_KEY_ID: str = Field(
        default="permit-key-v1", description="Identifier of active HMAC permit signing key in KMS"
    )
    KMS_CACHE_TTL_SECONDS: int = Field(
        default=300, description="KMS in-memory key cache TTL in seconds"
    )
    KMS_TIMEOUT_SECONDS: float = Field(
        default=5.0, description="External KMS request timeout in seconds"
    )
    KMS_VAULT_MOUNT: str = Field(
        default="secret", description="Vault KV v2 secret engine mount path"
    )
    KMS_KEY_PATH_PREFIX: str = Field(
        default="privai", description="Vault secret path prefix"
    )
    KMS_ALLOW_LOCAL_FALLBACK: bool = Field(
        default=False, description="Whether to allow fallback to local keys on remote KMS failure (strictly False in production)"
    )

    # External Audit Checkpoint Anchoring Settings
    AUDIT_ANCHOR_PROVIDER: str = Field(
        default="local", description="Audit anchor provider: 'local' (mock/offline) or 'production' (REST transparency log / WORM)"
    )
    AUDIT_ANCHOR_ENDPOINT: str = Field(
        default="", description="External audit anchor endpoint URL"
    )
    AUDIT_ANCHOR_AUTH_TOKEN: str = Field(
        default="", description="Authentication credential for external audit anchor"
    )
    AUDIT_ANCHOR_TIMEOUT_SECONDS: float = Field(
        default=5.0, description="External audit anchor request timeout in seconds"
    )
    AUDIT_ANCHOR_MAX_RETRIES: int = Field(
        default=2, description="Maximum retry attempts for transient anchor errors"
    )
    AUDIT_ANCHOR_REQUIRED: bool = Field(
        default=True, description="Whether checkpoint creation strictly fails closed if remote anchoring fails"
    )
    AUDIT_CHECKPOINT_EPOCH_SIZE: int = Field(
        default=100, description="Default number of audit events per periodic checkpoint epoch"
    )

    # PrivAI Secure Task Agent Settings
    AGENT_DATABASE_PATH: str = Field(
        default="privai_agent.db", description="Path to durable SQLite database for agent tasks and steps"
    )
    AGENT_MAX_STEPS: int = Field(
        default=5, description="Maximum execution steps permitted per agent task"
    )
    AGENT_MAX_RETRIES: int = Field(
        default=2, description="Maximum retries permitted per agent step"
    )
    AGENT_TIMEOUT_SECONDS: float = Field(
        default=30.0, description="Maximum execution timeout for agent tasks in seconds"
    )
    SAFE_DOCUMENTS_DIR: str = Field(
        default="safe_documents", description="Designated safe directory for read-only agent documents"
    )
    SAFE_REPORTS_DIR: str = Field(
        default="agent_reports", description="Designated safe directory for agent output reports"
    )
    EMPLOYEE_DEMO_DATABASE_PATH: str = Field(
        default="privai_demo_employees.db",
        description="Dedicated SQLite database for synthetic employee directory demo",
    )

    def validate_runtime_database_isolation(self) -> None:
        """Refuse unsafe development/staging writes to historical privai_data.db."""
        from pathlib import Path

        if self.ENVIRONMENT in ("development", "staging"):
            db_path = Path(self.DATABASE_PATH)
            hist_path = Path(self.HISTORICAL_DATABASE_PATH)
            db_resolved = (
                db_path.resolve() if db_path.is_absolute() else (Path.cwd() / db_path).resolve()
            )
            hist_resolved = (
                hist_path.resolve() if hist_path.is_absolute() else (Path.cwd() / hist_path).resolve()
            )
            if db_resolved == hist_resolved:
                raise RuntimeError(
                    "UNSAFE RUNTIME DATABASE CONFIGURATION: "
                    f"DATABASE_PATH is pointing to the historical baseline database '{self.HISTORICAL_DATABASE_PATH}'. "
                    "Development and staging environments must use an isolated runtime database "
                    "(e.g., DATABASE_PATH=privai_dev.db) to prevent modifying historical baseline data."
                )
            demo_path = Path(self.EMPLOYEE_DEMO_DATABASE_PATH)
            demo_resolved = (
                demo_path.resolve() if demo_path.is_absolute() else (Path.cwd() / demo_path).resolve()
            )
            if demo_resolved == hist_resolved:
                raise RuntimeError(
                    "UNSAFE DEMO DATABASE CONFIGURATION: "
                    f"EMPLOYEE_DEMO_DATABASE_PATH is pointing to historical baseline database '{self.HISTORICAL_DATABASE_PATH}'."
                )


settings = Settings()


