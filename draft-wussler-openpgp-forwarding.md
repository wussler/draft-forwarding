---
title: "Automatic Forwarding for ECDH Curve25519 OpenPGP messages"
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

author:
 -
    fullname: Aron Wussler
    org: Proton AG
    country: Switzerland
    email: aron@wussler.it

normative:

  RFC7748:

  I-D.ietf-openpgp-crypto-refresh:

informative:

  FORWARDING:
    target: http://dx.doi.org/10.1007/978-981-16-6890-6_12
    title: OpenPGP Email Forwarding Via Diverted Elliptic Curve Diffie-Hellman Key Exchanges
    author:
      - name: Francisco Vial-Prado
      - name: Aron Wussler
    date: March 2021

  EUROCRYPT:
    target: http://dx.doi.org/10.1007/BFb0054122
    title: Divertible Protocols and Atomic Proxy Cryptography
    author:
      - name: Matt Blaze
      - name: Gerrit Bleumer
      - name: Martin Strauss
    date: 1998

--- abstract

An offline OpenPGP user might want to automatically forward part or all of
their email messages to third parties.
Given that messages are encrypted, this requires transforming them into
ciphertexts decryptable by the intended forwarded parties, while maintaining
confidentiality and authentication.
This can be achieved using Proxy transformations on the Curve25519 elliptic
curve field with minimal changes to the OpenPGP protocol, in particular no
change is required on the sender side.
In this document we implement the forwarding scheme described in {{FORWARDING}}.

--- middle

# Introduction

An OpenPGP user might be interested in forwarding their email to
another user without interacting or delegating decryption.
In this document we outline the changes necessary to the OpenPGP protocol to safely allow:

  - Recipients to delegate trust to third parties to read their messages;

  - MTAs to act as cryptographic Proxies and transform select messages;

  - Forwardees to read the transformed email.

This is achieved using a BBS-like transformation {{EUROCRYPT}} on the ECDH
encryption algorithm using Curve25519.
It requires a proxy to multiply the ephemeral ECDH value by a known factor on
the elliptic curve field, and the forwardee to alter the Key Derivation Function
(KDF) when computing the Key Encryption Key (KEK) in a Public Key Encrypted
Session Key Packet (PKESK).

Security is provided as long as there is no collusion involving the Proxy,
i.e. we consider that the MTA that takes care of the forwarding is a semi-trusted
proxy that is not able to decrypt.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

**Sender**: The person who originally sends the email. They are no active part in
this protocol as this forwarding scheme is transparent to them and they are
unaware such transformation is being done.

**Recipient**: The intended recipient of the email, as specified from the sender.
They delegate the trust by setting up the protocol.

**Forwardee**: The person who receives the forwarded email.

**Forwardee subkey**: An OpenPGP encryption subkey generated from the recipient for
the forwardee that allows them to read the transformed messages.

**Proxy**: An OpenPGP-aware Mail Transfer Agent (MTA) with the task of forwarding
email (possibly a subset) to a forwardee.

**Proxy parameter**: An octet string representing a big-endian encoded integer in
the finite field of Curve25519.
This parameter allows transformation of the message.

# Description of the protocol

In this section we'll provide an illustration of the overall protocol.

>   NON-NORMATIVE EXPLANATION
>
>   The scenario we address is the following: Bob (the recipient) wants to allow Charles (the forwardee) to decrypt email that was originally encrypted to Bob’s public key without having access to Bob’s private key or any online interaction. Naturally, MTAs (the Proxies) should not have the ability to read the contents of such messages. To achieve this, the protocol requires to be set up: First, Bob generates two  secret elements, a regular secret key, and a proxy factor `K`; second, Bob securely transfers the key to Charles and the proxy factor to the trusted MTA.
>   With the proxy factor, the MTA gains the ability to transform any PGP message encrypted to Bob’s public key into another PGP message that can be decrypted with the newly generated private key, which is now held by Charles. At the same time, the MTA cannot decrypt the message, nor transform it to another public key. Upon participating in ECDH key exchanges, proxies need to store one random field element and two OpenPGP Key IDs per forwarding, and compute a single scalar multiplication on the elliptic curve per forwarded ciphertext.
>   In the following illustration, we show an example with a sender (Alice), a recipient (Bob), multiple direct forwardees (Charles and Daniel), and one indirect forwardee (Frank).
>   The proxy transformations are done by the two MTAs using the proxy transformation parameters `K_BC`, `K_BD`, and `K_DF`. This transforms the Public Key Encrypted Session Key Packet `P_B` into `P_C`, `P_D`, and `P_F`, while the Symmetrically Encrypted Data `c` is not transformed.

                               MTA 1
    ┌─────────┐          ┌──────────────┐           ┌─────────┐
    │         │ (P_B, c) │              │ (P_B, c)  │         │
    │  Alice  ├──────────┼─┬────────────┼──────────►│   Bob   │
    │         │          │ │            │           │         │
    └─────────┘          │ │            │           └─────────┘
                         │ │            │
                         │ │  ┌──────┐  │           ┌─────────┐
                         │ │  │      │  │ (P_C, c)  │         │
                         │ ├─►│ K_BC ├──┼──────────►│ Charles │
                         │ │  │      │  │           │         │
                         │ │  └──────┘  │           └─────────┘
                         │ │            │
                         │ │  ┌──────┐  │           ┌─────────┐
                         │ │  │      │  │ (P_D, c)  │         │
                         │ └─►│ K_BD ├──┼────────┬─►│ Daniel  │
                         │    │      │  │        │  │         │
                         │    └──────┘  │        │  └─────────┘
                         │              │        │
                         └──────────────┘        │
                                                 │
                           ┌─────────────────────┘
                           │
                           │
                         ┌─┼────────────┐
                         │ │            │
                         │ │  ┌──────┐  │           ┌─────────┐
                         │ │  │      │  │ (P_F, c)  │         │
                         │ └─►│ K_DF ├──┼──────────►│  Frank  │
                         │    │      │  │           │         │
                         │    └──────┘  │           └─────────┘
                         │              │
                         └──────────────┘
                               MTA 2

In this document we define the protocol for a single instance, but the same
procedure can be applied to multiple recipients independently.
Each instance MUST have an independent instantiation, generating fresh
keys and computing separate proxy transformation parameters.

## Key Flag 0x40 {#flag-forwarding}

The flag 0x40 is added to signal "This key may be used for forwarded communication",
this is to be used on subkeys for decryption of forwarded messages, i.e. forwardee subkeys.

This is designed to distinguish the usage from the existing 0x04 flag,
preventing implementations not capable of forwarding from using this key for
direct encryption, and thus generating unreadable messages.

An implementation SHOULD NOT export public subkeys flagged as 0x40.
A public key directory SHOULD NOT accept subkeys flagged as 0x40.

Keys having this flag MUST have the forwarding KDF parameters version 0xFF
defined in {{generating-forwarding-key}}.

# Setting up a forwarding instance

Starting from an OpenPGP v4 certificate as defined in {{I-D.ietf-openpgp-crypto-refresh}} with a
Curve25519 encryption-only subkey in this section is described how to compute a
proxy transformation parameter and a forwardee subkey.

The original key MUST have an ECDH (Algorithm ID 18) as defined in {{I-D.ietf-openpgp-crypto-refresh}}
section 9.1. subkey with exclusively the 0x04 (encrypt communications) or 0x08 (encrypt storage) flags,
as defined in {{I-D.ietf-openpgp-crypto-refresh}} section 5.2.3.26.
This subkey MUST NOT be revoked and it SHOULD be the most recently generated one,
so that the sender implementation will prefer it to encrypt messages.

## Generating the forwardee key {#generating-forwarding-key}

The implementation MUST generate a fresh OpenPGP certificate with only a Curve25519
encryption subkey.
This key MAY have the identity of the forwardee in the user ID.

The forwardee subkey MUST have the following Key Flags,
defined in {{I-D.ietf-openpgp-crypto-refresh}} section 5.2.3.26, in the self-signature:

  - 0x10 - The private component of this key may have been split by a secret-sharing mechanism.

  - 0x40 - This key may be used for forwarded communications.

Furthermore the flag 0x10 MAY be added to the existing recipient encryption subkey, if the
implementation desires to make the forwarding known to other parties.

The forwardee encryption subkey MUST contain the following variable-length field
containing KDF parameters, which is formatted as follows, differing from
{{I-D.ietf-openpgp-crypto-refresh}}, section 12.5:

  - A one-octet size of the following fields; values 0 and 0xFF are reserved for future extensions,

  - A one-octet value 0xFF, indicating a fingerprint replacement.

  - A one-octet hash function ID used with a KDF.

  - A one-octet algorithm ID for the symmetric algorithm used to wrap the
  symmetric key used for the message encryption; see {{I-D.ietf-openpgp-crypto-refresh}} section 12.5
  for details.

  - A 20-octet version 4 key fingerprint to be used in the KDF.

The forwardee subkey MUST be communicated securely to the forwardee, who accepts the
forwarding instantiation by adding it to their keyring.

## Computing the proxy parameter

Given the the recipient and forwardee encryption subkeys, the recipient's
implementation MUST compute the proxy transformation parameter as specified.

    //   Implements ComputeProxyPameter( dB, dC );
    //   Input:
    //   dB - the recipient's private key integer
    //   dC - the forwardee's private key integer
    //   n - the size of the field of Curve25519

    k = dB/dC mod n
    return k

The value n is defined in {{RFC7748}} as:

    2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed

Converted to hex:

    10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    14 de f9 de a2 f7 9c d6 58 12 63 1a 5c f5 d3 ed

The value k is then encoded as little-endian in a 32-byte octet string, and
referred as proxy transformation parameter.

The proxy transformation parameter MUST be communicated securely to the MTA
acting as proxy.
The proxy MUST safely store it in a way that is not accessible by other parties.
The proxy MUST delete the parameter when the forwarding is revoked.

# Forwarding messages

When forwarding a message, the proxy MUST parse the PKESK and check the if
the fingerprint embedded in the PKESK, as specified in {{I-D.ietf-openpgp-crypto-refresh}} section 5.1.2,
matches the recipient's subkey fingerprint designated for forwarding.
If the value differs, the proxy SHOULD NOT transform the message.
If the key ID is set to version 0 for "anonymous recipient", see {{I-D.ietf-openpgp-crypto-refresh}}
section 5.1.6, the proxy MAY transform all PKESKs in a message that it is
supposed to forward. In this case it SHOULD leave all key IDs unaltered to 0.

The proxy MUST then check that the ephemeral does not belong to a small subgroup
of the curve.
This is done by parsing the MPI of an EC point as specified in {{I-D.ietf-openpgp-crypto-refresh}}
section 5.1.5, multiplying by the integer 0x08.
If this multiplication returns 0 the proxy MUST abort the forwarding and it MAY
notify the sender, for instance by bouncing the message.
If this multiplication returns any non-zero value the proxy can proceed with
the transformation.

    //   Implements TransformMessage( eB, k );
    //   Input:
    //   eB - the ECDH ephemeral decoded from the PKESK
    //   k - the proxy transformation parameter retrieved from storage

    if 0x08 * eB == 0 then abort

    eC = k * eB
    return eC

The proxy MUST change the value of a non-null fingerprint in the PKESK
to the forwardee's key fingerprint.
The proxy MUST change the value of the EC ephemeral point in the algorithm
specific data of the PKESK to the the encoding of eC, as described in
{{I-D.ietf-openpgp-crypto-refresh}}, section 9.2.

# Decrypting forwarded messages

A forwardee accepts a forwarding instance by adding the forwardee subkey, flagged
with 0x40, to their private keys' keyring.
The implementation MAY group several forwarding subkeys under a single private
primary key, for a more compact and efficient storage.

Upon receiving a message encrypted to a subkey flagged as 0x40, the implementation
MUST replace the fingerprint in the ECDH KDF with the fingerprint specified in
the subkey KDF parameters.

The implementation SHOULD inform the user that the message was originally sent
to a different recipient and forwarded to them.

# Security Considerations

## Collusion between Proxy and Forwardee

It is important to note that any forwarded party that colludes with the proxy
can recover the forwarder's encryption subkey's secret.
It is to be noted that while recovering this private key may allow to decrypt other
messages, it does not allow to impersonate the forwarder's by generating valid
signatures, since key is as encryption-only subkey.

A complete security analysis can be found in {{FORWARDING}}, section 4 and
a simulation-based security proof in appendix A.

## Key Flags

The recipient's subkey used in the derivation of the proxy parameter MUST have
only the 0x04 (encrypt communications) flag as defined in {{I-D.ietf-openpgp-crypto-refresh}}
section 5.2.3.26.
In case of collusion between the proxy and forwardee, an adversary may only be
able to decrypt other messages, but not authenticate, sign, or certify other
keys as the recipient.

The forwardee encryption subkey MUST be flagged with 0x40 and 0x10 only,
this will prevent other implementations from sending messages directly to this
key, causing decryption errors when using the wrong fingerprint in the KDF.

Subkeys flagged as 0x40 MUST NOT be unflagged or reused as the private key
material is generated from a third party and therefore is not secret.

## Key rotation

It is RECOMMENDED to use short-lived encryption subkeys when forwarding messages.
This ensures that if a proxy is compromised, and the forwardee gets access to a
proxy transformation factor only a subset of the email is compromised.

## Proxy transformation factors management

When a forwarding is stopped or revoked a proxy MUST delete the stored proxy
factor to ensure that a future compromise does not retroactively endanger
older messages.

## Proxy transformation

The proxy MUST check that 8P is not 0, where P is the ephemeral point included
in the PKESK before performing the transformation, and if this is not satisfied
immediately abort the process.
Failure to perform this check may leak information about the proxy parameter to
an adversary that is able to submit messages and see the applied transformation.

A proxy SHOULD also perform the multiplication on the elliptic curve with the
proxy parameter in constant time.
This prevents an adversary from timing the transformation and derive information
about the proxy parameter.
Alternatively, a proxy MAY decide to pad all the forwarded messages to a
constant delay, thus preventing such an attack from an external submitter.

## Message forwarding selection

The criteria to choose which message to forward the messages is left up to the
implementation, and may be based on reception time, sender, or any policy
that can be determined from the message metadata.
Filtering message has a security implication in case of compromise: the
messages that were not forwarded may be decrypted by an adversary that can
compute the recipient's key.

# IANA Considerations

The 0x40 value is to be added to the OpenPGP IANA Key Flags Extensions registry,
representing "This key may be used for forwarded communication".
The flag is defined in {{flag-forwarding}}.

A new registry "ECDH KDF type" is to be created the OpenPGP IANA registry:

  - 0x01: "Native fingerprint KDF"

  - 0xFF: "Replaced fingerprint KDF"

--- back

# Test vectors

## Proxy parameter

Recipient secret integer, clamped and big endian, OpenPGP wire format

    59 89 21 63 65 05 3d cf 9e 35 a0 4b 2a 1f c1 9b
    83 32 84 26 be 6b b7 d0 a2 ae 78 10 5e 2e 31 88

Forwardee secret integer, clamped and big endian, OpenPGP wire format

    68 4d a6 22 5b cd 44 d8 80 16 8f c5 be c7 d2 f7
    46 21 7f 01 4c 80 19 00 5f 14 4c c1 48 f1 6a 00

Derived proxy parameter, little-endian

    e8 97 86 98 7c 3a 3e c7 61 a6 79 bc 37 2c d1 1a
    42 5e da 72 bd 52 65 d7 8a d0 f5 f3 2e e6 4f 02

## Message transformation

Proxy parameter, little-endian

    83 c5 7c be 64 5a 13 24 77 af 55 d5 02 02 81 30
    58 60 20 16 08 e8 1a 1d e4 3f f8 3f 24 5f b3 02

Ephemeral point P, 0x40 prefixed, OpenPGP wire format

    40 aa ea 7b 3b b9 2f 5f 54 5d 02 3c cb 15 b5 0f 84
    ba 1b dd 53 be 7f 5c fa dc fb 01 06 85 9b f7 7e

Transformed point kP, 0x40 prefixed, OpenPGP wire format

    40 ec 31 bb 93 7d 7e f0 8c 45 1d 51 6b e1 d7 97 61
    79 aa 71 71 ee a5 98 37 06 61 d1 15 2b 85 00 5a

A point of order 4 on the twist of Curve25519 to test small subgroup point
detection, 0x40 prefixed, OpenPGP wire format

    40 ec ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
    ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 7f

## End-to-end tests

Armored recipient key

    -----BEGIN PGP PRIVATE KEY BLOCK-----

    xVgEY/z/wxYJKwYBBAHaRw8BAQdAudHYYZgsVtDxQWkh+vdhtZumJRBMF7ZB9MaC
    aaO9XY0AAQCDAPxnqc0r1BufsBvSQuZgeZgLZMUcjpIvkKQbZkam9g+CzRNib2Ig
    PGJvYkBwcm90b24ubWU+wooEExYIADwFAmP8/8MJkFWnhLDuN2fYFiEEWyzWOv2P
    1C/Tk47fVaeEsO43Z9gCGwMCHgECGQECCwcCFQgCFgACIgEAAJlMAQDNj5HdAWFa
    Xl3AFkr/kLP5qmqA8ul8DonHM69E+U6kmgD8DPL1bD99xoBNLOyYAR/gY6Ghixib
    9ctPlmg5Ucw5Gw3HXQRj/P/DEgorBgEEAZdVAQUBAQdAafS4Ej42atxrs7vm/3ll
    XIB2DmDk6r4+C1Iv1kPfp1EDAQoJAAD/RuWwjLYJIUu5wFkE7P1zATS0Q1TuFwMo
    W4LZAia0vgAOw8J4BBgWCAAqBQJj/P/DCZBVp4Sw7jdn2BYhBFss1jr9j9Qv05OO
    31WnhLDuN2fYAhsMAADx+AD/UxhexVpsnqmSm/xMK0/DNUi9vqfPArGuHhHERPVw
    jwMBAL1NhOSN5npAC21pBrY03v/QjdAoznNn9thCN/5zMTUE
    =xEKi
    -----END PGP PRIVATE KEY BLOCK-----

Armored forwardee key

    -----BEGIN PGP PRIVATE KEY BLOCK-----

    xVgEY/z/wxYJKwYBBAHaRw8BAQdAhiCdLO3CLYUr+UTPWyyF/1T0P4A8AXakhq7m
    NZPj71cAAQCZeph5nMZTnZqoxz9n+I4HLdcee80YbhlADNC4oLHjPxADzRNib2Ig
    PGJvYkBwcm90b24ubWU+wooEExYIADwFAmP8/8MJkJ8qQsqhDuXHFiEE+hKTMx2k
    V7Dka648nypCyqEO5ccCGwMCHgECGQECCwcCFQgCFgACIgEAACC/AQDSz8S513Pc
    ABKAy9JOuZgXWkjQfNxeC9cyGBA2QXlNwwEAlF7FPmYeN8AK0lTjGZF/5Y4Bg9lh
    e8l7CshGpLMbawPHcQRj/P/DEgorBgEEAZdVAQUBAQdAHKTiQxGXGFIZOMt/nqUD
    P/9BGRNRmC5QSnOSapbRpTgX/woJfbqmBv0+GSCDuwidf6zZzjwShOUAAP99ySVZ
    6S/oGmJvsdH7VNOmEj7DubtWYjIW0GiDMva2eBGQwngEGBYIACoFAmP8/8MJkJ8q
    QsqhDuXHFiEE+hKTMx2kV7Dka648nypCyqEO5ccCG1AAAES9AQDu76yl1HL9Q02X
    VJJpjtWYP/22AFFTgI0vcIaRRD57EwEAnmWg/ppgGt8dI4vH1kYQrkO2tjqqeNek
    WKA2KfgiUwU=
    =ag55
    -----END PGP PRIVATE KEY BLOCK-----

Proxy parameter K

    58 6f f6 45 7b 13 30 4a d2 cb f1 4f 2e 67 bd 1c
    0b dc 16 e0 b9 8a a4 d7 cd e0 b2 6f 76 eb ea 06

Plaintext

    Message for Bob

Encrypted message

    -----BEGIN PGP MESSAGE-----

    wV4Df6zZzjwShOUSAQdA9WeDdxZXYZvPNTWFAr8WAjlzxtSGdtZT3RYBO45WgAow
    TVwErcFy2pWK2qEDxn6JAJTJ7Iw/NZcS0Raexm0iFoHrDWnYF95Irmj1isqdQabm
    0kABXnxfBGmcroo9Vf5tTsYY2oda7O4nHBtWYxjptxauRM0bgPoxiiiiXMUDnJzb
    2Ehf213S7fWI76cO2Zshlly1
    =pY4D
    -----END PGP MESSAGE-----

Transformed message

    -----BEGIN PGP MESSAGE-----

    wV4DZMBI/XxzdlYSAQdAGnvDD+yY7kSaTiNTnEerE6CUmIhNYRIfFf6k7hdc8low
    TVwErcFy2pWK2qEDxn6JAJTJ7Iw/NZcS0Raexm0iFoHrDWnYF95Irmj1isqdQabm
    0kABXnxfBGmcroo9Vf5tTsYY2oda7O4nHBtWYxjptxauRM0bgPoxiiiiXMUDnJzb
    2Ehf213S7fWI76cO2Zshlly1
    =6zA1
    -----END PGP MESSAGE-----

# Acknowledgments
{:numbered="false"}

A heartfelt thank you to Francisco Vial-Prado for the work on designing and
proving the forwarding scheme.
We also thank Ilya Chesnokov, Eduardo Conde, and Daniel Huigens for their
collaboration and help in applying the scheme to OpenPGP.
