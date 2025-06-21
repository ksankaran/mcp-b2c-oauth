import secrets
import time
import urllib.parse

from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)

from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from utils.server_settings import ServerSettings

class GoogleOAuthProvider(OAuthAuthorizationServerProvider):
    """Simple Google OAuth provider with essential functionality."""

    def __init__(self, settings: ServerSettings):
        self.settings = settings
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str]] = {}
        # Store tokens with MCP tokens using the format:
        # {"mcp_token": "google_token"}
        self.token_mapping: dict[str, str] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Generate an authorization URL for Google OAuth flow."""
        state = params.state or secrets.token_hex(16)

        # Store the state mapping
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
        }

        # Build Google authorization URL
        auth_url = (
            f"{self.settings.auth_url}"
            f"?client_id={self.settings.client_id}"
            f"&redirect_uri={self.settings.callback_path}"
            f"&response_type=code"
            f"&scope={self.settings.scope}"
            f"&state={state}"
        )

        return auth_url

    async def handle_callback(self, code: str, state: str) -> str:
        """Handle Google OAuth callback."""
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
        client_id = state_data["client_id"]

        """Exchange Google authorization code for access token using httpx."""
        access_token_url = self.settings.token_url
        http_response = await create_mcp_http_client().post(
            access_token_url,
            data=urllib.parse.urlencode({
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
                "code": code,
                "redirect_uri": self.settings.callback_path,
                "grant_type": "authorization_code",
            }),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        print(f"HTTP Response: {http_response.status_code} {http_response.text}")
        http_response.raise_for_status()
        access_response = http_response.json()
        
        token = access_response.get('access_token')

        # Create MCP authorization code
        new_code = f"mcp_{secrets.token_hex(16)}"
        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=str(AnyHttpUrl(redirect_uri)),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=self.settings.scope.split(),
            code_challenge=code_challenge,
        )
        self.auth_codes[new_code] = auth_code

        # Store Google token - we'll map the MCP token to this later
        self.tokens[token] = AccessToken(
            token=token,
            client_id=client_id,
            scopes=self.settings.scope.split(),
            expires_at=None,
            **access_response
        )

        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )

        print("Going to find Google token for this client...")
        # Find ADP token for this client
        google_token = next(
            (
                token
                for token, data in self.tokens.items()
                if (not token.startswith("mcp_")) and data.client_id == client.client_id
            ),
            None,
        )

        # Store mapping between MCP token and GitHub token
        if google_token:
            self.token_mapping[mcp_token] = google_token

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        """Load a refresh token - not supported."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token"""
        raise NotImplementedError("Not supported")

    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]