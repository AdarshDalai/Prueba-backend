from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    REDIS_URL: str = Field(..., env="REDIS_URL")
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    GOOGLE_CLIENT_ID: str = Field(..., env="GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: str = Field(..., env="GOOGLE_CLIENT_SECRET")
    APPLE_CLIENT_ID: str = Field(..., env="APPLE_CLIENT_ID")
    APPLE_CLIENT_SECRET: str = Field(..., env="APPLE_CLIENT_SECRET")
    API_V1_STR: str = Field("/api/v1", env="API_V1_STR")
    POSTGRES_USER: str = Field(..., env="postgres_user")
    POSTGRES_PASSWORD: str = Field(..., env="postgres_password")
    POSTGRES_DB: str = Field(..., env="postgres_db")
    REDIS_PASSWORD: str = Field(..., env="redis_password")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()