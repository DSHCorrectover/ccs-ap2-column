#!/usr/bin/env python3
# sdjwt.py — SD-JWT / KB-JWT 验签原语（ES256, P-256）
# AP2 crosswalk CCS column 用。只读 fixtures，不联网。
# 依据：IETF SD-JWT（disclosure digest = b64url(sha256(decoded disclosure bytes))；
#        kb-jwt sd_hash = b64url(sha256(ASCII(SD-JWT 部分含尾 ~)))）。
import base64, hashlib, json

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, SECP256R1, ECDSA)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def jwk_to_pubkey(jwk: dict) -> EllipticCurvePublicKey:
    assert jwk.get('kty') == 'EC' and jwk.get('crv') == 'P-256', f'unsupported jwk {jwk.get("kty")}/{jwk.get("crv")}'
    x = b64u_dec(jwk['x']); y = b64u_dec(jwk['y'])
    return EllipticCurvePublicKey.from_encoded_point(SECP256R1(), b'\x04' + x + y)


def verify_es256(jwk: dict, signing_input: bytes, sig_b64u: str) -> bool:
    sig_raw = b64u_dec(sig_b64u)
    if len(sig_raw) != 64:
        return False
    r = int.from_bytes(sig_raw[:32], 'big'); s = int.from_bytes(sig_raw[32:], 'big')
    pub = jwk_to_pubkey(jwk)
    try:
        pub.verify(encode_dss_signature(r, s), signing_input, ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def jwt_parse(token: str):
    """返回 (header, payload, signing_input, sig) ；解不出则抛 ValueError"""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError(f'jwt segments={len(parts)}')
    h, p, s = parts
    return (json.loads(b64u_dec(h)), json.loads(b64u_dec(p)),
            (h + '.' + p).encode('ascii'), s)


def check_disclosure_digests(payload: dict, disclosures: list) -> list:
    """核对 payload 内 _sd 数组与嵌套 {"...": digest} 是否全部重算命中。
    返回 (matched, unmatched_digests, unnamed_disclosures)。"""
    alg = payload.get('_sd_alg', 'sha-256')
    if alg != 'sha-256':
        raise ValueError(f'unsupported _sd_alg {alg}')
    computed = {}
    for d in disclosures:
        computed[b64u_enc(hashlib.sha256(d.encode('ascii')).digest())] = d

    def collect(obj):
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == '...' and isinstance(v, str):
                    found.append(v)
                else:
                    found += collect(v)
        elif isinstance(obj, list):
            for v in obj:
                found += collect(v)
        return found

    wanted = payload.get('_sd', []) + collect(payload)
    matched, unmatched = [], []
    for dg in wanted:
        (matched if dg in computed else unmatched).append(dg)
    used = set(wanted)
    unnamed = [d for dg, d in computed.items() if dg not in used]
    return matched, unmatched, unnamed


def resolve_disclosure(disclosure_str: str):
    """披露段 → (salt, key|None, value)"""
    arr = json.loads(b64u_dec(disclosure_str))
    if len(arr) == 3:
        return arr[0], arr[1], arr[2]
    if len(arr) == 2:
        return arr[0], None, arr[1]
    raise ValueError(f'bad disclosure arity {len(arr)}')


def kb_sd_hash(kb_payload: dict, sdjwt_prefix: str) -> bool:
    """KB-JWT 的 sd_hash 是否 = b64url(sha256(sd-jwt 部分含尾 ~))"""
    expect = kb_payload.get('sd_hash')
    got = b64u_enc(hashlib.sha256(sdjwt_prefix.encode('ascii')).digest())
    return bool(expect) and expect == got


def resolve_block(payload: dict, disclosures: list):
    """完整 SD-JWT 解析：签名 payload 的 digest（含嵌套 …）→ 披露 →
    已解析披露值内部的嵌套 … digest 也必须被其余披露提交。
    返回 dict：
      digests_missing  — payload/披露引用了但没有披露提交的 digest
      digests_unmatched— 披露算出的 digest 没被任何地方引用（未提交内容）
      resolved         — {digest: value}（含嵌套披露）
    """
    alg = payload.get('_sd_alg', 'sha-256')
    if alg != 'sha-256':
        raise ValueError(f'unsupported _sd_alg {alg}')
    dig = {b64u_enc(hashlib.sha256(d.encode('ascii')).digest()): d for d in disclosures}
    referenced, resolved = set(), {}

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == '_sd' and isinstance(v, list):
                    # SD-JWT 嵌套对象：_sd 引用该对象内部的披露
                    for dg in v:
                        if isinstance(dg, str):
                            referenced.add(dg)
                            if dg in dig and dg not in resolved:
                                resolved[dg] = resolve_disclosure(dig[dg])[2]
                                walk(resolved[dg])
                elif k == '...' and isinstance(v, str):
                    referenced.add(v)
                    if v in dig and v not in resolved:
                        resolved[v] = resolve_disclosure(dig[v])[2]
                        walk(resolved[v])
                else:
                    walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(payload)
    # 一轮吸收：披露引用披露（结算过 resolved 后再扩一轮 referenced）
    for _ in range(4):
        before = len(referenced)
        for v in list(resolved.values()):
            walk(v)
        if len(referenced) == before:
            break
    return {
        'digests_missing': sorted(referenced - set(dig)),
        'digests_unmatched': sorted(set(dig) - referenced),
        'resolved': resolved,
    }
