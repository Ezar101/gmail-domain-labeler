"""Setup configuration for Gmail Domain Labeler."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="gmail-domain-labeler",
    version="1.0.0",
    author="Ezar Affandi Inzouddine",
    author_email="salez.ea@gmail.com",
    description="Automatically organize Gmail inbox by creating labels based on sender domains",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Ezar101/gmail-domain-labeler",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.10",
        "Topic :: Communications :: Email",
    ],
    python_requires=">=3.10",
    install_requires=[
        "google-auth-oauthlib>=1.0.0",
        "google-auth-httplib2>=0.1.0",
        "google-api-python-client>=2.86.0",
        "tqdm>=4.65.0",
        "setuptools>=75.6.0",
    ],
    entry_points={
        "console_scripts": [
            "gmail-labeler=src.main:main",
        ],
    },
)
