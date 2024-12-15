# Gmail Domain Labeler

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Automatically organize your Gmail inbox by creating labels based on sender domains. This script analyzes your incoming emails and creates a hierarchical label structure, categorizing emails by the sender's domain name.

## 🌟 Features

- Creates a hierarchical label structure in your Gmail
- Automatically categorizes emails based on sender domains
- Progress tracking with visual progress bars
- Batch processing for optimal performance
- Error handling and logging
- Supports all email formats and special characters in domains

## 📋 Requirements

- Python 3.8 or higher
- A Google account with Gmail
- Gmail API enabled in Google Cloud Console
- OAuth 2.0 credentials configured

## 🚀 Installation

1/ Clone the repository:

```bash
git clone https://github.com/Ezar101/gmail-domain-labeler.git
cd gmail-domain-labeler
```

2/ Create a virtual environment ([docs here](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)):

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3/ Install required packages:

```bash
pip install -r requirements.txt
```

4/ Set up Google Cloud Project and OAuth 2.0:

- Go to the [Google Cloud Console](https://console.cloud.google.com/)
- Create a new project
- Enable the Gmail API
- Create OAuth 2.0 credentials
- Download the credentials and save as `credentials.json` in the project root

## 💡 Usage

1/ Run the script:

```bash
# Basic usage
python -m src.main

# To process all emails
python -m src.main --all-emails true

# To process all emails with a custom batch size
python -m src.main --all-emails true --batch-size 200

# With custom options
python -m src.main --max-emails 1000 --parent-label "Email Domains" --batch-size 50

# Help on available options
python -m src.main --help
```

Available options:

- `--credentials`: Path to Google OAuth credentials file (default: credentials.json)
- `--max-emails`: Maximum number of emails to process (default: 500)
- `--all-emails`: Process all emails instead of using max-emails limit (default: False)
- `--parent-label`: Name of the parent label (default: "Sender Domains")
- `--batch-size`: Number of emails to process in each batch (default: 100)

2/ First-time setup:

- A browser window will open
- Login to your Google account
- Grant the required permissions
- The script will start processing your emails

## 📊 Example Results

```bash
🚀 Starting Gmail Domain Labeler
🔍 Starting email analysis and labeling
🚀 Fetching existing labels...
🔥 Creating parent label: Sender Domains
🚀 Fetching up to 500 emails...
Processing emails: 100%|██████████| 500/500 [00:15<00:00, 33.33emails/s]
Creating labels: 100%|██████████| 12/12 [00:03<00:00, 4.00domains/s]
Labeling emails: 100%|██████████| 12/12 [00:08<00:00, 1.50domains/s]

🎉 Processing complete! 12 domains treated.

📣 Results for applied labels:
💠 Domain gmail.com: 145 labeled messages
  ✉️  Original emails : 145
  💌  Labeled emails : 145
  📩  Correspondence : 145
💠 Domain outlook.com: 89 labeled messages
  ✉️  Original emails : 89
  💌  Labeled emails : 89
  📩  Correspondence : 89
💠 Domain yahoo.com: 67 labeled messages
  ✉️  Original emails : 67
  💌  Labeled emails : 67
  📩  Correspondence : 67
[...]
```

Before:

```bash
└── Gmail Inbox
    ├── Email 1 (from user@gmail.com)
    ├── Email 2 (from info@company.com)
    └── Email 3 (from newsletter@service.net)
```

After:

```bash
└── Gmail Inbox
    └── Sender Domains
        ├── gmail.com
        │   └── Email 1
        ├── company.com
        │   └── Email 2
        └── service.net
            └── Email 3
```

## 🧪 Running Tests

```bash
# Installing development dependencies
pip install -r requirements-dev.txt

# Run tests with coverage
pytest --cov=src tests/

# Run tests with detailed report
pytest -v tests/
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This script requires access to your Gmail account. Make sure to review the code and understand the permissions you're granting. Never share your `credentials.json` or `token.json` files.
