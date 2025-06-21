"""Simple MCP Server with Google OAuth Authentication."""

import logging

from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

class ServerSettings(BaseSettings):
    """Settings for the simple Google MCP server."""

    model_config = SettingsConfigDict(env_prefix="MCP_")

    # Server settings
    host: str = "localhost"
    port: int = 3000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:3000")

    # OAuth settings - MUST be provided via environment variables
    client_id: str  # Type: MCP_CLIENT_ID env var
    client_secret: str  # Type: MCP_CLIENT_SECRET env var
    callback_path: str = "http://localhost:3000/callback"

    # Google OAuth URLs
    auth_url: str = "https://accounts.google.com/o/oauth2/auth"
    token_url: str = "https://oauth2.googleapis.com/token"

    scope: str = "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid"

    def __init__(self, **data):
        """Initialize settings with values from environment variables.

        Note: client_id and client_secret are required but can be
        loaded automatically from environment variables (MCP_CLIENT_ID
        and MCP_CLIENT_SECRET) and don't need to be passed explicitly.
        """
        super().__init__(**data)