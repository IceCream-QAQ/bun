# Public emSign certificate regression fixtures

These are public certificates only, not private keys. The manifest records their
source URLs, DER SHA-256 fingerprints, and SPKI SHA-256 fingerprints. The 8 G2
certificates were revoked on November 7, 2026; the 8 AAA cross-certificates were
revoked on October 21, 2026. Both groups were revoked for cessationOfOperation,
not proven public-key compromise. Their exact certificate fingerprints are
blocked without blocking every possible certificate sharing those RSA keys.

Source: eMudhra report https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c82,
plus issuer-signed CRLs checked by the implementation review.

The additional 16 G3 ECDSA certificates comprise 8 original certificates and 8
cross-signed copies. Their 8 distinct compromised public keys are blocked by
SPKI SHA-256, irrespective of the certificate fingerprint or issuing root.
They are sourced from the public URLs in the manifest; no private key is present.

RSA evidence was checked on 2026-11-16. Original certificate fingerprints match
the incident report's Appendix C. The original issuer CRLs are
https://crl.emsign.com/?roottlscag1.crl and
https://crl.emsign.com/?rootcscag2.crl . The AAA cross-certificates were obtained
from a public CT distribution service; their signatures and revocation entries
were independently checked against the AAA issuer and its official signed CRL:
http://crt.comodoca.com/AAACertificateServices.crt and
http://crl.comodoca.com/AAACertificateServices.crl . The AAA root DER SHA-256 is
`d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4`.
The signed CRL checked had lastUpdate 2026-11-15 23:39:56 UTC and nextUpdate
2026-11-22 23:39:56 UTC. Per-certificate dates and CRL URLs are in the manifest.
These historical revocations do not imply a live CRL-fetching feature in Bun.

The October ECDSA SPKI set was compared byte-for-byte with upstream Bun PR
https://github.com/oven-sh/bun/pull/46300 . This fixture check confirms matching
public keys and certificate identities, not a handshake using real CA private
keys. No such private keys were obtained or used.
