"""Gmail Domain Labeler.

A tool to automatically organize Gmail inbox by creating labels based on sender domains.
This script creates a hierarchical label structure and categorizes emails by the sender's domain name.
"""

import os
import sys
import re
import logging
import argparse
import codecs
from typing import Any, Dict, List, TextIO, cast

# from codecs import StreamWriter
from tqdm import tqdm
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build, Resource
from googleapiclient.errors import HttpError

# Configuration
# Scopes needed to edit emails and labels
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.modify",
]

# Configure Default Encoding for Windows
if sys.platform.startswith("win"):
    # Force use of utf-8 for sys.stdout
    sys.stdout = cast(TextIO, codecs.getwriter("utf-8")(sys.stdout.buffer, "strict"))
    sys.stderr = cast(TextIO, codecs.getwriter("utf-8")(sys.stderr.buffer, "strict"))


class UTFStreamHandler(logging.StreamHandler):
    """Stream handler that supports UTF-8 encoding."""

    def emit(self, record: logging.LogRecord) -> None:
        """Emit."""

        try:
            msg = self.format(record)
            stream = self.stream
            # Encode in utf-8 and decode in cp1252 (for Windows)
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


# Configure logging with UTF-8 support
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        UTFStreamHandler(sys.stdout),
        logging.FileHandler("gmail_labeler.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


class GmailLabeler:
    """Main class for handling Gmail domain labeling operations."""

    def __init__(
        self,
        credentials_path: str = "credentials.json",
        parent_label: str = "Sender Domains",
    ) -> None:
        """Initialize Gmail Labeler service.

        Args:
            credentials_path: Path to the Google OAuth credentials file
            parent_label: Parent label name

        Raises:
            Exception: For other authentication errors
        """
        self.parent_label = parent_label
        try:
            self.service = self._authenticate_gmail(credentials_path)
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise

    def _authenticate_gmail(self, credentials_path: str) -> Resource:
        """Authenticate with Gmail API with token persistence.

        Args:
            credentials_path: Path to the Google OAuth credentials file

        Returns:
            Gmail API service instance

        Raises:
            FileNotFoundError: If credentials file is not found
            Exception: For other authentication errors
        """
        if not os.path.exists(credentials_path):
            raise FileNotFoundError(f"Credentials file not found: {credentials_path}")

        creds = None
        if os.path.exists("token.json"):
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)

        if not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
            with open("token.json", "w") as token:
                token.write(creds.to_json())

        return build("gmail", "v1", credentials=creds)

    def _get_domain(self, sender: str) -> str | None:
        """Extract domain from email address.

        Args:
            sender: Sender email address to extract domain

        Returns:
            domain name or None. For addresses with multiple @, returns the last domain
            Example: 'user@host@domain.com' -> 'domain.com'
                    'user@sub.domain.com' -> 'sub.domain.com'
        """
        try:
            if not sender or "@" not in sender:
                return None

            # Take the part after the last @
            domain = sender.split("@")[-1].strip(">")

            # Check that the domain is valid
            if re.match(r"^[\w\.\-]+$", domain):
                return domain
            return None
        except Exception:
            return None

    def _sanitize_label_name(self, domain: str) -> str:
        """Clean the domain name to make it a valid label name.

        Args:
            domain: Domain name to sanitize

        Returns:
            Sanitized domain name suitable for Gmail label
        """
        try:
            # Removes non-alphanumeric characters except points
            cleaned = re.sub(r"[^a-zA-Z0-9\.]", "_", domain)
            return cleaned[:50]
        except Exception:
            raise

    def _get_existing_labels(self, user_id: str = "me") -> Any | list:
        """Get existing labels.

        Args:
            user_id: Gmail user ID

        Returns:
            List of label dictionaries. Empty list if error occurs.
        """
        try:
            logger.info(f"🚀 Fetching existing labels...")
            response = self.service.users().labels().list(userId=user_id).execute()
            return response.get("labels", [])
        except HttpError as e:
            logger.error(f"💥 Failed to fetch existing labels: {e}")
            return []
        except Exception as e:
            logger.error(f"💥 Unexpected error fetching labels: {e}")
            return []

    def get_emails_by_domain(
        self, max_emails: int = 500, process_all: bool = False, user_id: str = "me"
    ) -> Dict[str, List[str]]:
        """Retrieve received emails grouped by domain.

        Args:
            max_emails: Maximum number of emails to process
            process_all: If True, process all emails regardless of max_emails
            user_id: Gmail user ID

        Returns:
            Dictionary mapping domains to lists of message IDs. Empty dict if error occurs.

        Raises:
            None: All exceptions are caught and logged
        """
        try:
            if process_all:
                logger.info("🚀 Fetching all emails...")
            else:
                logger.info(f"🚀 Fetching up to {max_emails} emails...")

            query = "-in:sent"
            domain_emails: Dict[str, List[str]] = {}
            page_token = None

            while True:
                try:
                    # Fetch messages page by page
                    results = (
                        self.service.users()
                        .messages()
                        .list(
                            userId=user_id,
                            q=query,
                            maxResults=max_emails
                            if not process_all
                            else 500,  # Use 500 as page size,
                            pageToken=page_token,
                        )
                        .execute()
                    )

                    messages = results.get("messages", [])

                    if not messages:
                        # logger.warning("⚠️ No messages found")
                        break

                    # Progress bar for processing emails
                    for message in tqdm(
                        messages, desc="Processing emails", unit="email"
                    ):
                        try:
                            msg_id = message["id"]
                            msg = (
                                self.service.users()
                                .messages()
                                .get(userId=user_id, id=msg_id)
                                .execute()
                            )

                            # Extract sender from headers
                            headers = msg["payload"]["headers"]
                            sender = next(
                                (
                                    header["value"]
                                    for header in headers
                                    if header["name"] == "From"
                                ),
                                None,
                            )

                            if sender:
                                domain = self._get_domain(sender)
                                if domain:
                                    domain_emails.setdefault(domain, []).append(msg_id)
                        except HttpError as e:
                            logger.error(f"💥 Error processing message {msg_id}: {e}")
                            continue

                    # Break if not processing all emails or no more pages
                    if not process_all or "nextPageToken" not in results:
                        break

                    page_token = results.get("nextPageToken")
                except HttpError as e:
                    logger.error(f"💥 Failed to fetch message batch: {e}")
                    break

            if not domain_emails:
                logger.warning("⚠️ No messages found")

            return domain_emails

        except Exception as e:
            logger.error(f"💥 Unexpected error: {e}")
            return {}

    def create_parent_label(self, user_id: str = "me") -> Any | None:
        """Create the parent label if it doesn't exist.

        Returns:
            Parent label ID if successful, None otherwise

        Raises:
            HttpError: If Gmail API request fails
        """
        existing_labels = self._get_existing_labels()
        existing_label_names = [label["name"] for label in existing_labels]

        if self.parent_label not in existing_label_names:
            try:
                logger.info(f"🔥 Creating parent label: {self.parent_label}")
                parent_label = (
                    self.service.users()
                    .labels()
                    .create(
                        userId=user_id,
                        body={
                            "name": self.parent_label,
                            "labelListVisibility": "labelShow",
                            "messageListVisibility": "show",
                        },
                    )
                    .execute()
                )
                return parent_label["id"]
            except HttpError as e:
                logger.error(f"💥 Failed to create parent label: {e}")
                return None

        # Retrieve existing parent label ID
        parent_label = next(
            (label for label in existing_labels if label["name"] == self.parent_label),
            None,
        )
        return parent_label["id"] if parent_label else None

    def create_labels(
        self,
        parent_label_id: str,
        domain_emails: Dict[str, List[str]],
        user_id: str = "me",
    ) -> Dict[str, str]:
        """Create labels for each domain under the parent label.

        Args:
            parent_label_id: ID of the parent label
            domain_emails: Set of domains to create labels for

        Returns:
            Dictionary mapping domains to their label IDs

        Raises:
            HttpError: If Gmail API request fails
        """
        existing_labels = self._get_existing_labels()
        existing_label_names = [label["name"] for label in existing_labels]

        domain_labels = {}

        # Progress bar for creating labels
        for domain in tqdm(
            domain_emails.keys(), desc="Creating labels", unit="domaine"
        ):
            # Clean up domain name
            clean_domain = self._sanitize_label_name(domain)

            # Full label name (with parent)
            full_label_name = f"{self.parent_label}/{clean_domain}"

            if full_label_name not in existing_label_names:
                try:
                    logger.info(f"🔥 Creating label: {full_label_name}")
                    label = (
                        self.service.users()
                        .labels()
                        .create(
                            userId=user_id,
                            body={
                                "name": full_label_name,
                                "labelListVisibility": "labelShow",
                                "messageListVisibility": "show",
                                "parentLabelId": parent_label_id,
                            },
                        )
                        .execute()
                    )
                    domain_labels[domain] = label["id"]
                    logger.info(f"🎉 Label created: {full_label_name}")
                except HttpError as e:
                    logger.error(
                        f"💥 Error creating label {full_label_name} for {clean_domain}: {e}"
                    )
                    continue
            else:
                # Find existing label ID
                existing_label = next(
                    label
                    for label in existing_labels
                    if label["name"] == full_label_name
                )
                domain_labels[domain] = existing_label["id"]

        return domain_labels

    def apply_labels(
        self,
        domain_emails: Dict[str, List[str]],
        domain_labels: Dict[str, str],
        batch_size: int = 100,
        user_id: str = "me",
    ) -> None:
        """Apply labels to corresponding emails.

        Args:
            domain_emails: Dictionary mapping domains to message IDs
            domain_labels: Dictionary mapping domains to label IDs

        Raises:
            HttpError: If Gmail API request fails
        """
        emails_by_domain = {k: len(v) for k, v in domain_emails.items()}
        logger.info(f"🔥 Domain labels created : {domain_labels}")
        logger.info(f"✉️  Emails by domain : {emails_by_domain}")

        for domain, message_ids in tqdm(
            domain_emails.items(), desc="Labeling emails", unit="domaine"
        ):
            label_id = domain_labels.get(domain)

            if not label_id:
                logger.warning(f"⚠️ No labels found for the domain {domain}")
                continue

            logger.info(
                f"🔥 Processing batch for domain {domain} - {len(message_ids)} emails"
            )

            # Filter messages that don't already have the label
            messages_to_label = []

            for msg_id in message_ids:
                try:
                    # Retrieve current labels from message
                    msg = (
                        self.service.users()
                        .messages()
                        .get(userId=user_id, id=msg_id, format="minimal")
                        .execute()
                    )

                    # If the label does not already exist for this message, add it to the list
                    if label_id not in msg.get("labelIds", []):
                        messages_to_label.append(msg_id)
                except HttpError as e:
                    logger.error(f"💥 Error checking labels for message {msg_id}: {e}")
                    continue

            if not messages_to_label:
                logger.info(f"✨ No new messages to label for domain {domain}")
                continue

            logger.info(
                f"📝 Labeling {len(messages_to_label)} new emails for domain {domain}"
            )

            # Batch apply labels to messages that don't have the label yet
            for i in range(0, len(messages_to_label), batch_size):
                batch = messages_to_label[i : i + batch_size]
                try:
                    self.service.users().messages().batchModify(
                        userId=user_id, body={"ids": batch, "addLabelIds": [label_id]}
                    ).execute()
                    logger.info(
                        f"✅ Successfully labeled batch of {len(batch)} emails for {domain}"
                    )
                except HttpError as e:
                    logger.error(f"💥 Error labeling batch for domain {domain}: {e}")
                    continue

    def verify_labels_result(
        self,
        domain_emails: Dict[str, List[str]],
        domain_labels: Dict[str, str],
        user_id: str = "me",
    ) -> None:
        """Check that the labels have been applied correctly."""

        print("\n📣 Results for applied labels:")

        for domain, label_id in domain_labels.items():
            # Search for emails with this label
            query = f'label:"{self.parent_label}/{self._sanitize_label_name(domain)}"'
            results = (
                self.service.users().messages().list(userId=user_id, q=query).execute()
            )
            labeled_messages = results.get("messages", [])

            print(f"💠 Domain {domain} : {len(labeled_messages)} labeled messages")

            # Optional: verify that these emails correspond to the original emails
            original_emails = set(domain_emails.get(domain, []))
            labeled_email_ids = {msg["id"] for msg in labeled_messages}

            print(f" ✉️  Original emails : {len(original_emails)}")
            print(f" 💌 Labeled emails : {len(labeled_email_ids)}")
            print(
                f" 📩 Correspondence : {len(original_emails.intersection(labeled_email_ids))}"
            )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        description="Gmail Domain Labeler - Organize emails by sender domain"
    )
    parser.add_argument(
        "--credentials",
        default="credentials.json",
        help="Path to Google OAuth credentials file",
    )
    parser.add_argument(
        "--max-emails",
        type=int,
        default=500,
        help="Maximum number of emails to process",
    )
    parser.add_argument(
        "--all-emails",
        type=bool,
        default=False,
        help="Process all emails instead of using max-emails limit",
    )
    parser.add_argument(
        "--parent-label", default="Sender Domains", help="Name of the parent label"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of emails to process in each batch",
    )
    return parser.parse_args()


def main() -> None:
    """Main execution function."""

    args = parse_args()

    try:
        logger.info("🚀 Starting Gmail Domain Labeler")

        # Initialize labeler
        labeler = GmailLabeler(args.credentials, args.parent_label)

        logger.info("🔍 Starting email analysis and labeling")

        # Create the parent label
        parent_label_id = labeler.create_parent_label()
        if not parent_label_id:
            logger.info("⚠️ No parent label to process")
            return

        # Process emails
        domain_emails = labeler.get_emails_by_domain(
            max_emails=args.max_emails, process_all=args.all_emails
        )
        if not domain_emails:
            logger.info("⚠️ No emails to process")
            return

        # Create and apply labels
        domain_labels = labeler.create_labels(parent_label_id, domain_emails)
        if domain_labels:
            labeler.apply_labels(domain_emails, domain_labels, args.batch_size)

            # Print results
            logger.info(f"🎉 Processing complete! {len(domain_emails)} domains treated.")
            labeler.verify_labels_result(domain_emails, domain_labels)
        else:
            logger.error("💥 Failed to create labels")

    except Exception as e:
        logger.error(f"💥 An error occurred: {e}")
        raise


if __name__ == "__main__":
    main()
