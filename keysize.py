import argparse
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import dns.dnssec
import dns.edns
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
import dns.zonefile
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag

SERVER_COOKIE_SIZE = 16
DEFAULT_NAMESERVER = "a.root-servers.net"
DEFAULT_HINTS_FILENAME = "root.hints"
NXDOMAIN_QNAME = "nxdomain."


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
    origin: dns.name.Name, keys: List[Key], server_cookie_size: int = 0
):
    signer = origin
    ttl = 3600
    lifetime = 86400
    payload = 8192

    dnskey_rrset = dns.rrset.from_rdata_list(origin, ttl, [k.dnskey for k in keys])

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

    rrsig_rrset = dns.rrset.from_rdata_list(origin, ttl, rrsigs)

    query = dns.message.make_query(
        origin, "DNSKEY", want_dnssec=True, use_edns=True, flags=0, payload=payload
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


def generate_priming_response(
    origin: dns.name.Name,
    keys: List[Key],
    rrsets: List[dns.rrset.RRset],
    server_cookie_size: int = 0,
):
    signer = origin
    ttl = 3600
    lifetime = 86400
    payload = 8192

    ns_rrset = None
    glue_rrsets = []
    for rrset in rrsets:
        if rrset.rdtype == dns.rdatatype.NS:
            ns_rrset = rrset
        elif rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            glue_rrsets.append(rrset)

    rrsigs = [
        dns.dnssec.sign(
            rrset=ns_rrset,
            private_key=k.private_key,
            dnskey=k.dnskey,
            lifetime=lifetime,
            signer=signer,
            verify=True,
        )
        for k in keys
        if not k.flags & Flag.SEP
    ]

    rrsig_rrset = dns.rrset.from_rdata_list(origin, ttl, rrsigs)

    query = dns.message.make_query(
        origin, "NS", want_dnssec=True, use_edns=True, flags=0, payload=payload
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

    response.answer = [ns_rrset]
    ns_size = len(response.to_wire()) - header_size
    logging.debug("Response NS, %d bytes", ns_size)

    response.answer = [ns_rrset, rrsig_rrset]
    rrsig_size = len(response.to_wire()) - ns_size - header_size
    logging.debug("Response RRSIG, %d bytes", rrsig_size)

    response.additional = glue_rrsets
    additional_size = len(response.to_wire()) - ns_size - rrsig_size - header_size
    logging.debug("Response ADDITIONAL, %d bytes", additional_size)

    return response


def get_nxdomain_rrsets(
    qname: dns.name.Name,
    nameserver=DEFAULT_NAMESERVER,
    qtype: dns.rdatatype.RdataType = dns.rdatatype.NS,
):
    resolver = dns.resolver.Resolver()
    answer = resolver.resolve(nameserver, "A")
    nameserver = answer.rrset[0].address
    q = dns.message.make_query(qname, qtype, want_dnssec=True, flags=0)
    response = dns.query.tcp(q, nameserver)
    if response.rcode() != dns.rcode.NXDOMAIN:
        raise RuntimeError("Invalid response code")
    return [
        rrset for rrset in response.authority if rrset.rdtype != dns.rdatatype.RRSIG
    ]


def generate_nxdomain_response(
    origin: dns.name.Name, keys: List[Key], server_cookie_size: int = 0
):
    signer = origin
    ttl = 3600
    lifetime = 86400
    payload = 8192

    qname = dns.name.from_text(NXDOMAIN_QNAME)

    response_rrsets = get_nxdomain_rrsets(qname)
    rrsig_rrsets = []

    for rrset in response_rrsets:
        rrsigs = [
            dns.dnssec.sign(
                rrset=rrset,
                private_key=k.private_key,
                dnskey=k.dnskey,
                lifetime=lifetime,
                signer=signer,
                verify=True,
            )
            for k in keys
            if not k.flags & Flag.SEP
        ]
        rrsig_rrset = dns.rrset.from_rdata_list(rrset.name, ttl, rrsigs)
        rrsig_rrsets.append(rrsig_rrset)

    query = dns.message.make_query(
        qname, "NS", want_dnssec=True, use_edns=True, flags=0, payload=payload
    )
    response = dns.message.make_response(query, our_payload=8192)
    response.set_rcode(dns.rcode.NXDOMAIN)

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

    response.authority = response_rrsets
    nxdomain_size = len(response.to_wire()) - header_size
    logging.debug("Response NXDOMAIN, %d bytes", nxdomain_size)

    response.authority = response_rrsets + rrsig_rrsets
    rrsig_size = len(response.to_wire()) - nxdomain_size - header_size
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

    parser.add_argument(
        "--dnskey", action="store_true", help="Generate DNSKEY response"
    )
    parser.add_argument(
        "--nxdomain", action="store_true", help="Generate NXDOMAIN response"
    )
    parser.add_argument(
        "--priming", action="store_true", help="Generate PRIMING response"
    )

    parser.add_argument("--cookie", action="store_true", help="Add DNS cookie")
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    parser.add_argument(
        "--origin",
        metavar="ORIGIN",
        default=".",
        help="Origin",
    )

    parser.add_argument(
        "--hints",
        metavar="FILENAME",
        default=DEFAULT_HINTS_FILENAME,
        help="Name server hints",
    )

    parser.add_argument(
        "--cookie-size",
        type=int,
        default=SERVER_COOKIE_SIZE,
        help="Server cookie size (default 32)",
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

    origin = dns.name.from_text(args.origin)

    keys = []
    algorithms_seen = set()
    for a in args.algorithms:
        params = a.split(":")
        algorithm = Algorithm[params[0].upper()]
        key_size = int(params[1]) if len(params) > 1 else None
        ksk = algorithm not in algorithms_seen
        algorithms_seen.add(algorithm)
        keys.append(Key.keygen(algorithm=algorithm, key_size=key_size, ksk=ksk))

    if args.dnskey:
        response = generate_dnskey_response(
            origin, keys, server_cookie_size=args.cookie_size if args.cookie else 0
        )
        wire = response.to_wire()
        print(response)
        print()
        print(f"DNSKEY query response size {len(wire)} bytes")

    elif args.priming:
        with open(args.hints) as fp:
            hints_rrsets = dns.zonefile.read_rrsets(fp.read())
        response = generate_priming_response(
            origin,
            keys,
            hints_rrsets,
            server_cookie_size=args.cookie_size if args.cookie else 0,
        )
        wire = response.to_wire()
        print(response)
        print()
        print(f"PRIMING query response size {len(wire)} bytes")

    elif args.nxdomain:
        response = generate_nxdomain_response(
            origin, keys, server_cookie_size=args.cookie_size if args.cookie else 0
        )
        wire = response.to_wire()
        print(response)
        print()
        print(f"NXDOMAIN query response size {len(wire)} bytes")

    else:
        logging.warning("Nothing to do.")


if __name__ == "__main__":
    main()
