---
title: "Automatic Forwarding for OpenPGP messages"
abbrev: "OpenPGP Forwarding"
category: info

docname: draft-wussler-openpgp-forwarding-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Open Specification for Pretty Good Privacy"
keyword:
 - Forwarding
 - OpenPGP
venue:
  group: "Open Specification for Pretty Good Privacy"
  type: "Working Group"
  mail: "openpgp@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/openpgp/"
  github: "wussler/draft-forwarding"
  latest: "https://wussler.github.io/draft-forwarding/draft-wussler-openpgp-forwarding.html"

author:
 -
    fullname: Aron Wussler
    organization: Proton AG
    email: aron@wussler.it

normative:

informative:

FORWARDING:
  target: https://www.wussler.it/ECDHForwarding.pdf
  title: OpenPGP Email Forwarding Via Diverted Elliptic Curve Diffie-Hellman Key Exchanges
  author:
    -
      ins: F. Vial-Prado
      name: Francisco Vial-Prado
    -
      ins: A. Wussler
      name: Aron Wussler
  date: April 2021

--- abstract

An offline OpenPGP user might want to forward part or all of their email
messages to third parties.
Given that messages are encrypted, this requires transforming them into
ciphertexts decryptable by the intended forwarded parties, while maintaining
confidentiality and authentication.

In this document we outline the protocol changes needed to implement the
forwarding scheme described in [FORWARDING].

--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

It is important to note that any forwarded party that colludes with the proxy
can recover the forwarder's encryption subkey.
We point out that, while recovering this private key may allow to decrypt other
messages, it does not allow to impersonate the forwarder's by generating valid
signatures, since key is as encryption-only subkey.

A complete security analysis can be found in [FORWARDING], section 4 and appendix A.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

Thanks to Francisco Vial-Prado for the work on the forwarding scheme.
