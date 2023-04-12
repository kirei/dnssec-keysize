# DNSSEC Response Size Calculator

This tool will calculate the DNSSEC response sizes for different combinations of keys and algorithms. The resulting DNSKEY RRset will be signed with one signature per algorithm.

Example:

**2x RSA-2048/SHA-256**:

    python3 keysize.py --dnskey rsasha256:2048 rsasha256:2048

**2x RSA-2048/SHA256 + 2x ED448**:

    python3 keysize.py --dnskey rsasha256:2048 rsasha256:2048 ed448 ed448


## Priming Queries

If a `root.hints` file is available, the calculator can also calculate the size of the priming query response:

**2x RSA-2048/SHA-256**:

    python3 keysize.py --priming rsasha256:2048 rsasha256:2048

**2x RSA-2048/SHA256 + 2x ED448**:

    python3 keysize.py --priming rsasha256:2048 rsasha256:2048 ed448 ed448


## NXDOMAIN

Calculate the NXDOMAIN for a plain NS query:

**2x RSA-2048/SHA-256**:

    python3 keysize.py --nxdomain rsasha256:2048 rsasha256:2048

**2x RSA-2048/SHA256 + 2x ED448**:

    python3 keysize.py --nxdomain rsasha256:2048 rsasha256:2048 ed448 ed448


## Dependencies

The tool depends on  `cryptography` and `dnspython`. Install manually or via  `poetry shell` and `poetry install`.
