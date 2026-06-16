from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CLAUDE_SIDECAR_",
        frozen=True,
    )

    api_token: str = ""
    max_turns: int = 80
    anthropic_api_key: str = ""
    anthropic_base_url: str = ""
