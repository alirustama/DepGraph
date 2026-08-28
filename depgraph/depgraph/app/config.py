"""
All connection details come from environment variables. Nothing here is ever
hard-coded, and the .env file (loaded only for local dev convenience) is
git-ignored — see .env.example for the shape callers must provide.
"""
import os
from dotenv import load_dotenv

load_dotenv()  # no-op in production where real env vars are already set


class Settings:
    cognodb_uri: str = os.environ.get("COGNODB_URI", "")
    cognodb_user: str = os.environ.get("COGNODB_USER", "")
    cognodb_password: str = os.environ.get("COGNODB_PASSWORD", "")
    cognodb_database: str = os.environ.get("COGNODB_DATABASE", "neo4j")

    @property
    def is_configured(self) -> bool:
        return bool(self.cognodb_uri and self.cognodb_user and self.cognodb_password)


settings = Settings()
