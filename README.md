# MCP B2C OAuth

A project for implementing Google OAuth2 client app B2C authentication for the MCP platform.

## Overview

This project provides integration with Google OAuth2 for authentication and authorization within the MCP (Model Context Protocol) platform. It enables secure user authentication through Google's identity platform.

## Features

- Google OAuth2 integration
- OAuth 2.0 authentication flow
- Token management
- User profile retrieval
- Role-based access control

## Installation

```bash
uv sync
```

## Configuration

Modify `.env` file in the root directory with the following variables:

```
MCP_CLIENT_ID=<YOUR_GOOGLE_CLIENT_ID>
MCP_CLIENT_SECRET=<YOUR_GOOGLE_CLIENT_SECRET>

```

## Usage

Start the development server:

```bash
uv run .
```

## Authentication Flow

1. User is redirected to Google OAuth2 login page
2. After successful authentication, Google redirects to the callback URL
3. Application validates the received token
4. User session is established

## API Reference

### Authentication Endpoints

- `GET /callback` - Handles the OAuth callback
- `GET /.well-known/oauth-authorization-server` - Auth Server Details
- - `GET /authorize` - Used by MCP Clients to authorize with the server
- - `GET /token` - Used by MCP Clients to get token from code
- - `GET /register` - Used by MCP Clients to register themselves to server

## Development

### Prerequisites

- Python 3.13+
- Google Cloud Platform account with OAuth 2.0 client credentials

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

Name - kv.coder@gmail.com

Project Link: [https://github.com/ksankaran/mcp-b2c-oauth](https://github.com/ksankaran/mcp-b2c-oauth)