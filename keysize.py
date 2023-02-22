import argparse
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import dns.dnssec
import dns.edns
import dns.message
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag

SERVER_COOKIE_SIZE = 16


def keygen(algorithm: Algorithm, key_size: Optional[int] = None):
    if dns.dnssec._is_rsa(algorithm):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size or 2048,
            backend=default_backend(),
        )
    elif dns.dnssec._is_dsa(algorithm):
        return dsa.generate_private_key(key_size or 2048)
    elif algorithm == Algorithm.ECDSAP256SHA256:
        return ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
    elif algorithm == Algorithm.ECDSAP384SHA384:
        return ec.generate_private_key(curve=ec.SECP384R1, backend=default_backend())
    elif algorithm == Algorithm.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    elif algorithm == Algorithm.ED448:
        return ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError("Unsupport algorithm")


@dataclass(frozen=True)
class Key:
    private_key: dns.dnssec.PrivateKey
    key_size: Optional[int]
    algorithm: Algorithm
    flags: int

    @property
    def public_key(self) -> dns.dnssec.PublicKey:
        return self.private_key.public_key()

    @property
    def dnskey(self) -> DNSKEY:
        return dns.dnssec.make_dnskey(
            public_key=self.public_key, algorithm=self.algorithm, flags=self.flags
        )

    @classmethod
    def keygen(
        cls, algorithm: Algorithm, key_size: Optional[int] = None, ksk: bool = False
    ):
        return cls(
            private_key=keygen(algorithm, key_size),
            algorithm=algorithm,
            key_size=key_size,
            flags=Flag.ZONE | (Flag.SEP if ksk else 0),
        )


def generate_dnskey_response(
    zone: dns.name.Name, keys: List[Key], server_cookie_size: int = 0
):
    signer = zone
    ttl = 3600
    lifetime = 86400
    payload = 8192

    dnskey_rrset = dns.rrset.from_rdata_list(zone, ttl, [k.dnskey for k in keys])

    rrsigs = [
        dns.dnssec.sign(
            rrset=dnskey_rrset,
            private_key=k.private_key,
            dnskey=k.dnskey,
            lifetime=lifetime,
            signer=signer,
            verify=True,
        )
        for k in keys
        if k.flags & Flag.SEP
    ]

    rrsig_rrset = dns.rrset.from_rdata_list(zone, ttl, rrsigs)

    query = dns.message.make_query(
        zone, "DNSKEY", want_dnssec=True, use_edns=True, flags=0, payload=payload
    )
    response = dns.message.make_response(query, our_payload=8192)

    if server_cookie_size:
        if server_cookie_size > 32 or server_cookie_size < 8:
            raise ValueError("Invalid server_cookie_size size")
        client_cookie = os.urandom(8)
        server_cookie = os.urandom(server_cookie_size)
        options = [
            dns.edns.GenericOption(
                dns.edns.OptionType.COOKIE, client_cookie + server_cookie
            )
        ]
        response.use_edns(
            edns=0,
            ednsflags=0,
            payload=payload,
            request_payload=query.payload,
            options=options,
        )

    header_size = len(response.to_wire())
    logging.debug("Response header, %d bytes", header_size)
    response.answer = [dnskey_rrset]
    dnskey_size = len(response.to_wire()) - header_size
    logging.debug("Response DNSKEY, %d bytes", dnskey_size)
    response.answer = [dnskey_rrset, rrsig_rrset]
    rrsig_size = len(response.to_wire()) - dnskey_size - header_size
    logging.debug("Response RRSIG, %d bytes", rrsig_size)

    return response


ALGORITHMS_SUPPORTED = [
    "rsasha256",
    "rsasha512",
    "ecdsap256sha256",
    "ecdsap384sha384",
    "ed25519",
    "ed448",
]


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="DNSSEC Key Size Calculator")

    parser.add_argument("--cookie", action="store_true", help="Add DNS cookie")
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    parser.add_argument(
        "--cookie-size",
        type=int,
        default=SERVER_COOKIE_SIZE,
        help="Server cookie size (default 32)"
    )

    parser.add_argument(
        "algorithms",
        nargs="+",
        type=str,
        help="algorithm(:keysize), where algorithm is one of "
        + ",".join(ALGORITHMS_SUPPORTED),
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    zone = dns.name.from_text(".")

    keys = []
    algorithms_seen = set()
    for a in args.algorithms:
        params = a.split(":")
        algorithm = Algorithm[params[0].upper()]
        key_size = int(params[1]) if len(params) > 1 else None
        ksk = algorithm not in algorithms_seen
        algorithms_seen.add(algorithm)
        keys.append(Key.keygen(algorithm=algorithm, key_size=key_size, ksk=ksk))

    response = generate_dnskey_response(
        zone, keys, server_cookie_size=args.cookie_size if args.cookie else 0
    )
    wire = response.to_wire()

    print(response)
    print()
    print(f"DNSKEY query response size {len(wire)} bytes")


if __name__ == "__main__":
    main()
