import base64
import hashlib
import http.server
import logging
import os
import secrets
import socketserver
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread, Timer

import requests

from .base_auth import BaseAuth

logger = logging.getLogger(__name__)


class CognitoAuth(BaseAuth):
    """
    Cognito authentication class that handles specific authentication processes
    for Cognito, including configuration and token management.
    """

    callback_port = 8090

    def __init__(self, config_manager):
        """
        Initializes the CognitoAuth class with specific scopes and a configuration manager.

        Args:
            config_manager (AppConfig): The AppConfig instance responsible for managing file operations.
        """
        super().__init__(config_manager)
        self.scopes = "openid email"

    def configure(self, **kwargs):
        super().configure(**kwargs)

        # Attempt to retrieve configuration from kwargs or default to None
        cognito_domain = kwargs.get("cognito_domain")
        client_id = kwargs.get("client_id")

        # Update self.config with fixed value for 'idp'
        self.config_manager.config["idp"] = "cognito"

        # If cognito_domain is not provided, prompt for it
        if cognito_domain is None or kwargs.get("force_prompt_config"):
            cognito_domain = input("Enter Cognito Domain: ")
        self.config_manager.config["cognito_domain"] = cognito_domain

        # If client_id is not provided, prompt for it
        if client_id is None or kwargs.get("force_prompt_config"):
            client_id = input("Enter Cognito client ID: ")
        self.config_manager.config["cognito_client_id"] = client_id

        self.config_manager.save()

    # Exchange the authorization code for an access token
    def exchange_code_for_token(self, authorization_code, code_verifier):
        cognito_domain = self.config_manager.config["cognito_domain"]
        client_id = self.config_manager.config["cognito_client_id"]
        token_url = f"{cognito_domain}/oauth2/token"

        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": f"http://localhost:{self.callback_port}/callback",
            "client_id": client_id,
            "code_verifier": code_verifier,
            "scope": self.scopes,
        }
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        tokens = response.json()
        return tokens

    def authenticate(self):
        cognito_domain = self.config_manager.config["cognito_domain"]
        client_id = self.config_manager.config["cognito_client_id"]

        # Generate code verifier and code challenge
        code_verifier = (
            base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").replace("=", "")
        )
        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(code_challenge).decode("utf-8").replace("=", "")
        )

        # Construct the authorization URL
        authorization_url = f"{cognito_domain}/oauth2/authorize"

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": f"http://localhost:{self.callback_port}/callback",
            "scope": self.scopes,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
        }
        url = f"{authorization_url}?{urllib.parse.urlencode(params)}"

        def handle_request(PORT):
            # Create a custom request handler class
            class RequestHandler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, format, *args):
                    # Suppress access logs
                    pass

                def do_GET(self):
                    if self.path.startswith("/callback"):
                        parsed_path = urllib.parse.urlparse(self.path)
                        query_params = urllib.parse.parse_qs(parsed_path.query)
                        authorization_code = query_params["code"][0]
                        self.server.authorization_code = authorization_code
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(
                            b"Authorization code received. You can now close this window."
                        )
                    else:
                        self.send_response(404)
                        self.end_headers()

            # Create a TCP server and start listening
            with socketserver.TCPServer(("localhost", PORT), RequestHandler) as httpd:
                # Wait for a request or 60 seconds, whichever comes first
                httpd.timeout = 60
                try:
                    httpd.handle_request()
                except socketserver.socket.timeout:
                    print(
                        "No request received within 60 seconds. Shutting down server."
                    )

                # Close the server
                httpd.server_close()
                return httpd

        t = Thread(
            target=lambda: webbrowser.open(
                url,
            )
        )
        t.start()
        httpd = handle_request(self.callback_port)

        if not hasattr(httpd, "authorization_code"):
            return False

        # Use the access token to make API requests
        tokens = self.exchange_code_for_token(httpd.authorization_code, code_verifier)

        id_token = tokens["id_token"]
        refresh_token = tokens["refresh_token"]

        self.token["token"] = id_token
        self.token["refresh_token"] = refresh_token
        self.token["requires_refresh"] = False
        self.save_idp_token()

        return True

    def refresh_token(self):
        cognito_domain = self.config_manager.config["cognito_domain"]
        client_id = self.config_manager.config["cognito_client_id"]
        refresh_token = self.token["refresh_token"]

        url = f"{cognito_domain}/oauth2/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": self.scopes,
            "client_id": client_id,
        }

        response = requests.post(url, headers=headers, data=data, timeout=(5, 15))

        if response.status_code == 200:
            # Assuming a successful response, update the refresh token and access token
            tokens = response.json()
            self.token["token"] = tokens.get("id_token")
            self.token["refresh_token"] = (
                refresh_token  # Cognito does not renew the refresh token
            )
            self.token["requires_refresh"] = False
            self.save_idp_token()

            return tokens.get("expires_in") + datetime.now(timezone.utc).timestamp()

        return False
