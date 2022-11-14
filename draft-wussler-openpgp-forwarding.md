---
title: "Automatic Forwarding for ECDH Curve25519 OpenPGP messages"
abbrev: "OpenPGP Forwarding"
category: std

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

  RFC7748:

  REFRESH:
    target: https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-07.html
    title: OpenPGP Message Format
    author:
      - name: Paul Wouters
      - name: Daniel Huigens
      - name: Justus Winter
      - name: Yutaka Niibe
    date: tbd

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

(Illustration of the flow)

In this document we refer to a single forwardee, but the same procedure MAY
be applied to multiple recipients independently.
Each instance MUST have an independent instantiation, generating independent
keys and computing separate proxy transformation parameters.

## Key Flag 0x40 {#flag-forwarding}

The flag 0x40 is added to signal "This key may be used for forwarded communication",
this is to be used on subkeys for decryption of forwarded messages, i.e. forwadee subkeys.

This is designed to distinguish the usage from the existing 0x04 flag,
preventing implementations not capable of forwarding from using this key for
direct encryption, and thus generating unreadable messages.

An implementation SHOULD NOT export public subkeys flagged as 0x40.
A public key directory SHOULD NOT accept subkeys flagged as 0x40.

Keys having this flag MUST have the forwarding KDF parameters version 2 defined in
{{generating-forwarding-key}}.

# Setting up a forwarding instance

Starting from an OpenPGP v4 of v5 certificate as defined in {{REFRESH}} with a
Curve25519 encryption-only subkey in this section is described how to compute a
proxy transformation parameter and a forwardee subkey.

The original key MUST have an ECDH (Algorithm ID 18) as defined in {{REFRESH}}
section 9.1. subkey with exclusively the 0x04 (encrypt communications) flag,
as defined in {{REFRESH}} section 5.2.3.26.
This subkey MUST NOT be revoked and it SHOULD be the most recently generated one,
so that the sender implementation will use it to encrypt messages.

## Generating the forwardee key {#generating-forwarding-key}

The implementation MUST generate a fresh OpenPGP certificate with only a Curve25519
encryption subkey.
This key MAY have the identity of the forwardee in the user ID.

The forwardee subkey MUST have the following Key Flags,
defined in {{REFRESH}} section 5.2.3.26, in the self-signature:

  - 0x10 - The private component of this key may have been split by a secret-sharing mechanism.

  - 0x40 - This key may be used for forwarded communications.

Furthermore the flag 0x10 MAY be added to the existing recipient encryption subkey, if the
implementation desires to make the forwarding known to other parties.

The forwardee encryption subkey MUST contain the following variable-length field
containing KDF parameters, which is formatted as follows, differing from
{{REFRESH}}, section 12.5:

  - A one-octet size of the following fields; values 0 and 0xFF are reserved for future extensions,

  - A one-octet value 0x02, indicating a fingerprint replacement,

  - A one-octet hash function ID used with a KDF,

  - A one-octet algorithm ID for the symmetric algorithm used to wrap the
  symmetric key used for the message encryption; see {{REFRESH}} section 12.5
  for details,

  - A one-octet value 0x01, indicating to expect a 20-octet fingerprint,

  - A 20-octet fingerprint to be used in the KDF, for version 4 keys this is
  the fingerprint of the recipient's key, for v5 the 20 leftmost octets of
  the recipient fingerprint.

The forwardee subkey MUST be communicated securely to the forwardee, who accepts the
forwarding instantiation by adding it to their keyring.

## Computing the proxy parameter

Given the the recipient and forwardee encryption subkeys, the recipient's
implementation MUST compute the proxy transformation parameter as specified.

    //   Implements ComputeProxyPameter( dB, dC );
    //   Input:
    //   dB - the recipient's private key integer
    //   dC - the forwadee's private key integer
    //   n - the size of the field of Curve25519

    k = dB/dC mod n
    return k

The value n is defined in {{RFC7748}} as:

    2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed

The value k is then encoded as big-endian in an octet string, and referred as
proxy transformation parameter.

The proxy transformation parameter MUST be communicated securely to the MTA
acting as proxy.
The proxy MUST safely store it in a way that is not accessible by clients.
The proxy MUST delete the parameter when the forwarding is revoked.

# Forwarding messages

When forwarding a message, the proxy MUST parse the PKESK and check the if
the fingerprint embedded in the PKESK, as specified in {{REFRESH}} section 5.1.2,
matches the recipient's subkey fingerprint designated for forwarding.
If the value differs, the proxy SHOULD NOT transform the message.
This also applies if the version is 0 for "anonymous recipient", see {{REFRESH}}
section 5.1.6.

The proxy MUST then check that the ephemeral does not belong to a small subgroup
of the curve.
This is done by parsing the MPI of an EC point as specified in {{REFRESH}}
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
{{REFRESH}}, section 9.2.

# Decrypting forwarded messages

A forwardee accepts a forwarding instance by adding the forwardee subkey, flagged
with 0x40, to their private keys keyring.

Upon receiving a message encrypted to a subkey flagged as 0x40, the implementation
MUST replace the fingerprint in the ECDH KDF with the fingerprint specified in
the subkey KDF parameters.

A forwardee MAY group several forwarding subkeys under a single private primary
key, for a more compact and efficient storage.

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
only the 0x04 (encrypt communications) flag as defined in {{REFRESH}}
section 5.2.3.26.
In case of collusion between the proxy and forwardee, an adversary may only be
able to decrypt other messages, but not authenticate, sign, or certify other
keys as the recipient.

The forwadee encryption subkey MUST be flagged with 0x40 and 0x10 only,
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

  - 0x02: "Replaced fingerprint KDF"

--- back

# Acknowledgments
{:numbered="false"}

A heartfelt thank you to Francisco Vial-Prado for the work on designing and
proving the forwarding scheme.
We also thank Ilya Chesnokov, Eduardo Conde, and Daniel Huigens for their
collaboration and help in applying the scheme to OpenPGP.
