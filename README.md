# DNSKEY Key Size Calculator

This tool will calculate the DNSKEY response sizes for different combinations of keys and algorithms.

Example:

**2x RSA-2048/SHA-256**:

    poetry run python3 keysize.py rsasha256:2048 rsasha256:2048

**2x RSA-2048/SHA256 + 2x ED448**:

    poetry run python3 keysize.py rsasha256:2048 rsasha256:2048 ed448 ed448
