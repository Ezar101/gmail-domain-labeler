"""Tests for Gmail Domain Labeler."""

from typing import List, Tuple
import pytest
from unittest.mock import Mock, patch, mock_open
from src.main import GmailLabeler
from googleapiclient.errors import HttpError


def test_authenticate_gmail() -> None:
    """Test different authentication scenarios."""

    # Cas 1: Credentials existants et valides
    with patch("os.path.exists") as mock_exists, patch(
        "src.main.Credentials"
    ) as mock_creds, patch("src.main.build") as mock_build:
        mock_exists.return_value = True
        mock_creds.from_authorized_user_file.return_value = Mock(valid=True)
        mock_build.return_value = Mock()

        labeler = GmailLabeler()
        assert labeler.service is not None

    # Cas 2: Credentials existants mais invalides
    with patch("os.path.exists") as mock_exists, patch(
        "src.main.Credentials"
    ) as mock_creds, patch("src.main.InstalledAppFlow") as mock_flow, patch(
        "src.main.build"
    ) as mock_build, patch(
        "builtins.open", mock_open()
    ) as mock_file:
        mock_exists.return_value = True
        mock_creds.from_authorized_user_file.return_value = Mock(valid=False)

        # Mock pour le flow d'authentification
        mock_flow_instance = Mock()
        mock_flow_instance.run_local_server.return_value = Mock(
            valid=True, to_json=Mock(return_value='{"mock": "token"}')
        )
        mock_flow.from_client_secrets_file.return_value = mock_flow_instance

        # Mock pour le service
        mock_build.return_value = Mock()

        labeler = GmailLabeler()
        assert labeler.service is not None
        mock_file().write.assert_called_once_with('{"mock": "token"}')

    # Cas 3: Credentials manquants
    with patch("os.path.exists") as mock_exists:
        mock_exists.return_value = False
        with pytest.raises(FileNotFoundError):
            GmailLabeler(credentials_path="nonexistent.json")


def test_get_domain() -> None:
    """Test domain extraction from email addresses."""

    labeler = GmailLabeler()
    test_cases: List[Tuple[str, str | None]] = [
        ("user@example.com", "example.com"),
        ("test.user@sub.domain.com", "sub.domain.com"),
        ("invalid-email", None),
        ("user@host@domain.com", "domain.com"),  # Take the last domain
        ("", None),
        # (None, None),
        ("<user@example.com>", "example.com"),
        ("user@sub.sub2.domain.com", "sub.sub2.domain.com"),  # Multiple subdomains
        (
            "user.name@host@sub.domain.com",
            "sub.domain.com",
        ),  # Multiple @ with subdomains
    ]

    for email, expected in test_cases:
        result = labeler._get_domain(email)
        assert result == expected, f"For {email}, expected {expected} but got {result}"


def test_sanitize_label_name() -> None:
    """Test label name sanitization."""

    labeler = GmailLabeler()
    test_cases: List[Tuple[str, str]] = [
        ("example.com", "example.com"),
        ("sub-domain.com", "sub_domain.com"),
        ("domain@with@symbols#.com", "domain_with_symbols_.com"),
        ("a" * 60 + ".com", ("a" * 50)),  # Test length truncation
    ]

    for domain, expected in test_cases:
        result = labeler._sanitize_label_name(domain)
        assert result == expected, f"For {domain}, expected {expected} but got {result}"


def test_get_existing_labels(labeler: GmailLabeler, mock_google_auth: Mock) -> None:
    """Test fetching existing labels."""

    # Mock successful response
    mock_google_auth.users().labels().list.return_value.execute.return_value = {
        "labels": [{"name": "Label1"}, {"name": "Label2"}]
    }

    # Test successful case
    labels = labeler._get_existing_labels()
    assert len(labels) == 2
    assert labels[0]["name"] == "Label1"

    # Test error handling
    mock_google_auth.reset_mock()
    mock_google_auth.users().labels().list.return_value.execute.side_effect = HttpError(
        resp=Mock(status=500), content=b'{"error": {"message": "Test error"}}'
    )
    labels = labeler._get_existing_labels()
    assert labels == []  # Should return empty list on error


def test_get_emails_by_domain_with_pagination(
    labeler: GmailLabeler, mock_google_auth: Mock
) -> None:
    """Test email fetching with pagination."""

    # Mock first page
    first_page = {
        "messages": [{"id": "msg1"}, {"id": "msg2"}],
        "nextPageToken": "token123",
    }
    # Mock second page
    second_page = {"messages": [{"id": "msg3"}]}

    # Setup mock responses
    mock_list = mock_google_auth.users().messages().list
    mock_list.return_value.execute.side_effect = [first_page, second_page]

    # Mock message details
    mock_get = mock_google_auth.users().messages().get
    mock_get.return_value.execute.return_value = {
        "payload": {"headers": [{"name": "From", "value": "user@example.com"}]}
    }

    # Test with process_all=True
    result = labeler.get_emails_by_domain(process_all=True)
    assert len(result["example.com"]) == 3


def test_create_parent_label(labeler: GmailLabeler, mock_google_auth: Mock) -> None:
    """Test parent label creation."""

    # Mock existing labels
    mock_google_auth.users().labels().list.return_value.execute.return_value = {
        "labels": []
    }

    # Mock label creation
    mock_google_auth.users().labels().create.return_value.execute.return_value = {
        "id": "parent123"
    }

    label_id = labeler.create_parent_label()
    assert label_id == "parent123"

    # Test existing parent label
    mock_google_auth.users().labels().list.return_value.execute.return_value = {
        "labels": [{"name": "Sender Domains", "id": "existing123"}]
    }

    label_id = labeler.create_parent_label()
    assert label_id == "existing123"


def test_create_labels(labeler: GmailLabeler, mock_google_auth: Mock) -> None:
    """Test domain label creation."""

    # Mock existing labels
    mock_google_auth.users().labels().list.return_value.execute.return_value = {
        "labels": []
    }

    # Mock label creation
    mock_google_auth.users().labels().create.return_value.execute.return_value = {
        "id": "label123"
    }

    domain_emails = {"example.com": ["msg1", "msg2"]}
    result = labeler.create_labels("parent123", domain_emails)

    assert "example.com" in result
    assert result["example.com"] == "label123"


def test_apply_labels(labeler: GmailLabeler, mock_google_auth: Mock) -> None:
    """Test label application to emails."""

    # Mock message labels check
    mock_get = mock_google_auth.users().messages().get
    mock_get.return_value.execute.return_value = {"labelIds": []}

    # Mock batch modification
    mock_batch = mock_google_auth.users().messages().batchModify
    mock_batch.return_value.execute.return_value = {}

    domain_emails = {"example.com": ["msg1", "msg2"]}
    domain_labels = {"example.com": "label123"}

    labeler.apply_labels(domain_emails, domain_labels)

    # Verify batch modify was called
    mock_batch.assert_called()


def test_verify_labels_result(labeler: GmailLabeler, mock_google_auth: Mock) -> None:
    """Test label verification."""

    # Mock message search
    mock_google_auth.users().messages().list.return_value.execute.return_value = {
        "messages": [{"id": "msg1"}, {"id": "msg2"}]
    }

    domain_emails = {"example.com": ["msg1", "msg2"]}
    domain_labels = {"example.com": "label123"}

    # Should not raise any exceptions
    labeler.verify_labels_result(domain_emails, domain_labels)


def test_error_handling(labeler: GmailLabeler, mock_google_auth: Mock) -> None:
    """Test error handling in various scenarios."""

    # Test HTTP error in get_emails_by_domain
    mock_google_auth.users().messages().list.return_value.execute.side_effect = (
        HttpError(
            resp=Mock(status=500), content=b'{"error": {"message": "Test error"}}'
        )
    )
    emails_by_domain_result = labeler.get_emails_by_domain()
    assert emails_by_domain_result == {}

    # Test HTTP error in batch modification
    mock_google_auth.reset_mock()

    # Mock pour la vérification des labels existants
    mock_get = mock_google_auth.users().messages().get.return_value.execute
    mock_get.return_value = {"labelIds": []}  # Message sans labels

    # Mock pour la liste des labels existants
    mock_google_auth.users().labels().list.return_value.execute.return_value = {
        "labels": []  # Pas de labels existants
    }

    mock_google_auth.users().messages().batchModify.return_value.execute.side_effect = (
        HttpError(
            resp=Mock(status=500), content=b'{"error": {"message": "Test error"}}'
        )
    )

    domain_emails = {"example.com": ["msg1"]}
    domain_labels = {"example.com": "label123"}
    # Ne devrait pas lever d'exception
    labeler.apply_labels(domain_emails, domain_labels)

    # Test erreur dans create_labels
    mock_google_auth.reset_mock()
    # Mock à nouveau la liste des labels existants
    mock_google_auth.users().labels().list.return_value.execute.return_value = {
        "labels": []  # Pas de labels existants
    }

    mock_google_auth.users().labels().create.return_value.execute.side_effect = (
        HttpError(
            resp=Mock(status=500), content=b'{"error": {"message": "Test error"}}'
        )
    )
    labels_result = labeler.create_labels("parent_id", {"example.com": ["msg1"]})
    assert labels_result == {}

    # Test erreur lors de la vérification des labels existants
    mock_google_auth.reset_mock()
    mock_google_auth.users().messages().get.return_value.execute.side_effect = (
        HttpError(
            resp=Mock(status=500), content=b'{"error": {"message": "Test error"}}'
        )
    )
    # Ne devrait pas lever d'exception
    labeler.apply_labels(domain_emails, domain_labels)

    # Test erreur lors de la récupération des labels existants
    mock_google_auth.reset_mock()
    mock_google_auth.users().labels().list.return_value.execute.side_effect = HttpError(
        resp=Mock(status=500), content=b'{"error": {"message": "Test error"}}'
    )
    existing_labels_result = labeler._get_existing_labels()
    assert existing_labels_result == []
