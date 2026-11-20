#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Batch auditing of RSA signatures.

The :func:`audit_signatures` function validates a batch of firmware
signature records without letting a single bad record abort the run.
Every record is classified with one of the ``reason`` codes:

* ``ok``                -- signature verifies, key and hash are acceptable;
* ``weak_key``          -- public key has fewer bits than ``min_key_bits``;
* ``weak_hash``         -- hash is deprecated or not in ``allowed_hashes``;
* ``invalid_signature`` -- record is well-formed but the signature does not
                           verify against the message and public key;
* ``malformed``         -- the record cannot be interpreted (bad PEM, bad
                           hexadecimal, missing or wrongly typed fields).

A ``malformed`` record never raises: the failure is captured in the result
and subsequent records keep being processed.
"""

import typing

import rsa.key
import rsa.pkcs1

#: Hash algorithms considered broken/deprecated for signing.
DEPRECATED_HASHES = frozenset(("MD5", "SHA-1"))

#: Hash algorithms accepted when the caller does not override the policy.
DEFAULT_ALLOWED_HASHES = ("SHA-256", "SHA-384", "SHA-512")

#: Reason codes used in audit results.
REASON_OK = "ok"
REASON_WEAK_KEY = "weak_key"
REASON_WEAK_HASH = "weak_hash"
REASON_INVALID_SIGNATURE = "invalid_signature"
REASON_MALFORMED = "malformed"

# Ordering used when a record carries more than one policy problem:
# a record that cannot even be parsed always wins, then a signature that
# does not verify, then key strength, then hash strength.
_REASON_PRIORITY = (
    REASON_MALFORMED,
    REASON_INVALID_SIGNATURE,
    REASON_WEAK_KEY,
    REASON_WEAK_HASH,
    REASON_OK,
)


class _MalformedRecord(Exception):
    """Raised internally when a single record cannot be interpreted."""


class AuditResult(typing.NamedTuple):
    """Outcome of a batch audit.

    :ivar items: one result dict per input record, in input order.
    :ivar stats: aggregate counts (``ok``, ``bad`` and ``by_reason``).
    """

    items: typing.List[typing.Dict[str, typing.Any]]
    stats: typing.Dict[str, typing.Any]


def _decode_hex(value: typing.Any, field: str) -> bytes:
    """Decodes a hexadecimal field, turning every failure into malformed."""

    if not isinstance(value, str):
        raise _MalformedRecord("field %r must be a hexadecimal string" % field)
    try:
        return bytes.fromhex(value)
    except ValueError as ex:
        raise _MalformedRecord("field %r is not valid hexadecimal: %s" % (field, ex))


def _load_public_key(pem_text: typing.Any) -> rsa.key.PublicKey:
    """Loads a PKCS#1 PEM public key without ever raising to the caller."""

    if not isinstance(pem_text, str):
        raise _MalformedRecord("field 'public_key' must be PEM text")
    try:
        return rsa.key.PublicKey.load_pkcs1(pem_text.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as ex:
        raise _MalformedRecord("cannot parse public key PEM: %s" % ex)


def _hash_is_weak(hash_name: typing.Any, allowed_hashes: typing.Sequence[str]) -> bool:
    """Returns True when the declared hash is deprecated or not allowed."""

    if not isinstance(hash_name, str):
        return True
    normalised = hash_name.strip()
    return normalised in DEPRECATED_HASHES or normalised not in allowed_hashes


def _base_item(index: int, hash_name: typing.Any) -> typing.Dict[str, typing.Any]:
    return {
        "index": index,
        "ok": False,
        "reason": REASON_MALFORMED,
        "key_bits": None,
        "hash": hash_name if isinstance(hash_name, str) else None,
        "issues": [],
    }


def _audit_one(
    index: int,
    record: typing.Any,
    min_key_bits: int,
    allowed_hashes: typing.Sequence[str],
) -> typing.Dict[str, typing.Any]:
    """Audits a single record; all failures are captured, never raised."""

    if not isinstance(record, dict):
        item = _base_item(index, None)
        item["issues"].append("record must be a dict of fields, got %r" % type(record).__name__)
        return item

    item = _base_item(index, record.get("hash"))

    try:
        message = _decode_hex(record.get("message"), "message")
        signature = _decode_hex(record.get("signature"), "signature")
        public_key = _load_public_key(record.get("public_key"))
    except _MalformedRecord as ex:
        item["issues"].append(str(ex))
        return item

    item["key_bits"] = public_key.n.bit_length()

    reasons = []  # type: typing.List[str]
    if item["key_bits"] < min_key_bits:
        reasons.append(REASON_WEAK_KEY)
        item["issues"].append(
            "key has %d bits, minimum required is %d" % (item["key_bits"], min_key_bits)
        )
    if _hash_is_weak(item["hash"], allowed_hashes):
        reasons.append(REASON_WEAK_HASH)
        item["issues"].append("hash %r is deprecated or not allowed" % item["hash"])

    try:
        rsa.pkcs1.verify(message, signature, public_key)
    except rsa.pkcs1.VerificationError as ex:
        reasons.append(REASON_INVALID_SIGNATURE)
        item["issues"].append("signature verification failed: %s" % ex)
    except (ValueError, TypeError, OverflowError) as ex:
        # Malformed signature material that the verifier cannot process at all.
        item["issues"].append("signature cannot be processed: %s" % ex)
        item["reason"] = REASON_MALFORMED
        return item

    if not reasons:
        item["reason"] = REASON_OK
        item["ok"] = True
        return item

    item["reason"] = min(reasons, key=_REASON_PRIORITY.index)
    return item


def _empty_stats() -> typing.Dict[str, typing.Any]:
    return {"ok": 0, "bad": 0, "by_reason": {}}


def audit_signatures(
    records: typing.Sequence[typing.Dict[str, typing.Any]],
    min_key_bits: int = 2048,
    allowed_hashes: typing.Optional[typing.Sequence[str]] = None,
) -> AuditResult:
    """Audits a batch of RSA signature records.

    Each record is a dict with the fields:

    * ``public_key`` -- PKCS#1 PEM text (``BEGIN RSA PUBLIC KEY``);
    * ``message``    -- the signed message, hexadecimal encoded;
    * ``signature``  -- the signature, hexadecimal encoded;
    * ``hash``       -- declared hash name, e.g. ``SHA-256`` or ``MD5``.

    Bad records are skipped, not raised: their result carries reason
    ``malformed`` (or another failure code) and the remaining records are
    still processed.

    :param records: the records to audit, in processing order.
    :param min_key_bits: public keys with fewer bits than this are flagged
        with reason ``weak_key``.
    :param allowed_hashes: hash names considered acceptable; defaults to
        ``("SHA-256", "SHA-384", "SHA-512")``. ``MD5`` and ``SHA-1`` are
        always treated as weak.
    :returns: an :class:`AuditResult` with per-record ``items`` and
        aggregate ``stats`` (``ok``, ``bad``, ``by_reason``).
    """

    if allowed_hashes is None:
        allowed_hashes = DEFAULT_ALLOWED_HASHES

    items = []  # type: typing.List[typing.Dict[str, typing.Any]]
    stats = _empty_stats()

    for index, record in enumerate(records):
        item = _audit_one(index, record, min_key_bits, allowed_hashes)
        items.append(item)

        reason = item["reason"]
        stats["by_reason"][reason] = stats["by_reason"].get(reason, 0) + 1
        if item["ok"]:
            stats["ok"] += 1
        else:
            stats["bad"] += 1

    return AuditResult(items=items, stats=stats)


__all__ = [
    "audit_signatures",
    "AuditResult",
    "DEPRECATED_HASHES",
    "DEFAULT_ALLOWED_HASHES",
]
