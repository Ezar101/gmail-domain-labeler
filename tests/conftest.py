"""Fixtures for Gmail Domain Labeler tests."""

from typing import Any, Generator
import pytest
from unittest.mock import Mock, patch, mock_open

from src.main import GmailLabeler


@pytest.fixture(autouse=True)  # type: ignore[misc]
def mock_google_auth() -> Generator[Any, Any, Any]:
    """Fixture to mock Google authentication and disable tqdm globally.
    autouse=True ensures this runs for all tests automatically.

    Returns:
        Generator yielding a mock Gmail service
    """

    with patch("src.main.tqdm", new=lambda x, **kwargs: x), patch(
        "os.path.exists"
    ) as mock_exists, patch("src.main.Credentials") as mock_creds, patch(
        "src.main.InstalledAppFlow"
    ) as mock_flow, patch(
        "src.main.build"
    ) as mock_build, patch(
        "builtins.open", mock_open()
    ):
        # Configuration des mocks
        mock_exists.return_value = True

        # Mock des credentials valides
        mock_valid_creds = Mock(valid=True)
        mock_creds.from_authorized_user_file.return_value = mock_valid_creds

        # Mock pour le flow d'authentification
        mock_flow_instance = Mock()
        mock_flow_instance.run_local_server.return_value = Mock(
            valid=True, to_json=Mock(return_value='{"mock": "token"}')
        )
        mock_flow.from_client_secrets_file.return_value = mock_flow_instance

        # Mock du service Gmail
        mock_service = Mock()
        mock_build.return_value = mock_service

        yield mock_service


@pytest.fixture  # type: ignore[misc]
def labeler() -> GmailLabeler:
    """Fixture for GmailLabeler instance.

    Args:
        mock_google_auth: Mocked Gmail service

    Returns:
        Configured GmailLabeler instance
    """

    return GmailLabeler()
