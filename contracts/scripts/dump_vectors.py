"""
Compute canonical Plutus CBOR for the 5 AuthCoveragePayload reference test
vectors. The encoding mirrors what `cbor.serialise` produces in Aiken (which
is the canonical authority): Constr 0 (tag 121) + indefinite-length array of
fields + break, with byte strings as definite-length major-type-2 and ints
using smallest-possible header per RFC 8949 §4.2.

Output: tests/fixtures/auth_payload_vectors.json — hex strings the TS / Python
encoders compare against byte-for-byte.

Run: python dump_vectors.py
"""
import hashlib
import json
import os


# ---- Plutus-canonical CBOR encoder (mirrors Aiken's `serialise_data`) ----

def enc_uint(n: int) -> bytes:
    """Major type 0 (positive int) with smallest-possible header."""
    if n < 0:
        return enc_negint(n)
    if n < 24:
        return bytes([n])
    if n < 0x100:
        return bytes([24, n])
    if n < 0x10000:
        return bytes([25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([27]) + n.to_bytes(8, "big")
    # Beyond 64-bit positive — encode as bignum (tag 2 + bytes).
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\xc2" + enc_bytes(raw)


def enc_negint(n: int) -> bytes:
    """Major type 1 (negative int)."""
    assert n < 0
    m = -1 - n
    if m < 24:
        return bytes([0x20 | m])
    if m < 0x100:
        return bytes([0x38, m])
    if m < 0x10000:
        return bytes([0x39]) + m.to_bytes(2, "big")
    if m < 0x100000000:
        return bytes([0x3a]) + m.to_bytes(4, "big")
    if m < 0x10000000000000000:
        return bytes([0x3b]) + m.to_bytes(8, "big")
    # Bignum
    raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    return b"\xc3" + enc_bytes(raw)


def enc_bytes(b: bytes) -> bytes:
    """Major type 2 (byte string), definite-length, smallest-possible header."""
    n = len(b)
    if n < 24:
        return bytes([0x40 | n]) + b
    if n < 0x100:
        return bytes([0x58, n]) + b
    if n < 0x10000:
        return bytes([0x59]) + n.to_bytes(2, "big") + b
    if n < 0x100000000:
        return bytes([0x5a]) + n.to_bytes(4, "big") + b
    return bytes([0x5b]) + n.to_bytes(8, "big") + b


def enc_constr0(fields: list) -> bytes:
    """Plutus Constr 0: tag 121 + indefinite-length array of fields + break.
    For Constr0..Constr6, Plutus uses tag 121..127 directly; for higher
    indices it uses tag 1280 + (idx - 7) (range tag).
    """
    return b"\xd8\x79\x9f" + b"".join(fields) + b"\xff"


def encode_field(value) -> bytes:
    """Dispatch encoder by Python type."""
    if isinstance(value, bool):
        # Booleans are constr — but unused in our payload.
        raise NotImplementedError
    if isinstance(value, int):
        return enc_uint(value)
    if isinstance(value, (bytes, bytearray)):
        return enc_bytes(bytes(value))
    raise TypeError(f"unsupported type {type(value)}")


def encode_payload(p: dict) -> bytes:
    """Encode AuthCoveragePayload as Plutus Constr 0 with fields in v2 spec
    §2.1 order:
      domain_tag, network_magic, policy_validator, policy_id, insured_pkh,
      payout_address, max_coverage, oracle_provider, oracle_nft,
      oracle_freshness, not_before, not_after, pool_script_hash, pool_nft.
    """
    field_order = [
        "domain_tag",
        "network_magic",
        "policy_validator",
        "policy_id",
        "insured_pkh",
        "payout_address",
        "max_coverage",
        "oracle_provider",
        "oracle_nft",
        "oracle_freshness",
        "not_before",
        "not_after",
        "pool_script_hash",
        "pool_nft",
    ]
    fields = [encode_field(p[k]) for k in field_order]
    return enc_constr0(fields)


# ---- Reference vectors (must match Aiken tv1..tv5) ----

TV1 = {
    "domain_tag": bytes.fromhex("41454749535f434c41494d5f415554485f76315f50524550524f44"),
    "network_magic": 1,
    "policy_validator": bytes.fromhex("8ea5aed0e4f66e9ce6593fbed30856c8997441b1e5cd8bc3085e943f"),
    "policy_id": bytes.fromhex("aabbccdd00112233445566778899aabbccddeeff0011223344556677"),
    "insured_pkh": bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabb"),
    "payout_address": bytes.fromhex("6000112233445566778899aabbccddeeff00112233445566778899aabb"),
    "max_coverage": 100_000_000,
    "oracle_provider": 0,
    "oracle_nft": bytes.fromhex("886dcb2363e160c944e63cf544ce6f6265b22ef7c4e2478dd975078e"),
    "oracle_freshness": 0,
    "not_before": 1_700_000_000_000,
    "not_after": 1_700_604_800_000,
    "pool_script_hash": bytes.fromhex("c366b0ea2667b432a432999f54e11978c0ed37c7c4b971067fb1589f"),
    "pool_nft": bytes.fromhex("deadbeef00112233445566778899aabbccddeeff00112233445566"),
}

TV2 = {
    "domain_tag": bytes.fromhex("41454749535f434c41494d5f415554485f76315f4d41494e4e4554"),
    "network_magic": 764_824_073,
    "policy_validator": bytes.fromhex("1111111111111111111111111111111111111111111111111111111a"),
    "policy_id": bytes.fromhex("2222222222222222222222222222222222222222222222222222222b"),
    "insured_pkh": bytes.fromhex("3333333333333333333333333333333333333333333333333333333c"),
    "payout_address": bytes.fromhex("613333333333333333333333333333333333333333333333333333333c"),
    "max_coverage": 5_000_000_000,
    "oracle_provider": 1,
    "oracle_nft": bytes.fromhex("4444444444444444444444444444444444444444444444444444444d"),
    "oracle_freshness": 60_000,
    "not_before": 1_725_000_000_000,
    "not_after": 1_725_604_800_000,
    "pool_script_hash": bytes.fromhex("5555555555555555555555555555555555555555555555555555555e"),
    "pool_nft": bytes.fromhex("6666666666666666666666666666666666666666666666666666"),
}

TV3 = dict(TV1, max_coverage=9_223_372_036_854_775_807)

TV4 = dict(TV1, not_before=1_700_000_000_000, not_after=1_700_000_000_001)

TV5 = dict(
    TV1,
    oracle_provider=2,
    oracle_nft=bytes.fromhex("d2f08410f9f999b2afff902ec4ef47cc7b1677709887d20e0f13938f"),
)


VECTORS = [
    ("minimal_preprod", TV1),
    ("mainnet_with_freshness", TV2),
    ("max_int_coverage", TV3),
    ("minimal_window", TV4),
    ("aegis_self_provider", TV5),
]


def to_hex_input(p: dict) -> dict:
    """Render bytes as hex strings for JSON output."""
    out = {}
    for k, v in p.items():
        out[k] = v.hex() if isinstance(v, (bytes, bytearray)) else v
    return out


def main():
    out = []
    for name, p in VECTORS:
        cbor = encode_payload(p)
        commit = hashlib.blake2b(cbor, digest_size=32).digest()
        out.append({
            "name": name,
            "input": to_hex_input(p),
            "cbor_hex": cbor.hex(),
            "blake2b_256_hex": commit.hex(),
        })

    fixtures_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "tests", "fixtures"
    )
    os.makedirs(fixtures_dir, exist_ok=True)
    out_path = os.path.join(fixtures_dir, "auth_payload_vectors.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    for v in out:
        print(f"--- {v['name']} ---")
        print(f"cbor:   {v['cbor_hex']}")
        print(f"commit: {v['blake2b_256_hex']}")
        print(f"len:    {len(v['cbor_hex'])//2} bytes")

    print(f"\nWrote {len(out)} vectors to {out_path}")


if __name__ == "__main__":
    main()
