#!/usr/bin/env python3
# column.py — CCS 列：对 AP2 crosswalk pinned fixtures 出独立判定（2026-11-25）
# 对象：stafordtituss/amep test fixtures（pin 见 inputs，与 APAF-1 inputs 逐字节对账）
# 判定纪律：
#   - 只信重算：每条签名/披露 digest/sd_hash/reference 绑定全部重算，不信 signer
#   - unknown 是有名字的状态：绝不静默升格（A2 语义）
#   - 违约点名 departed / 缺失点名 missing（A3 语义）
#   - gap 打印为 gap（收据无金额 = 发行属性，非实现缺陷）
# 输出：ccs-column.json；exit 0 = 所有自检 achieved
import json, sys, hashlib
sys.path.insert(0, '.')
from sdjwt import (b64u_dec, b64u_enc, jwt_parse, verify_es256,
                   resolve_block, resolve_disclosure, kb_sd_hash)

FIX = ['sdk-bundles.json', 'sdk-bundles-v2.json', 'bundles.json']
PINS = {
 'sdk-bundles.json':    '7e1dd6d97003d11f61ee2b60625bc1fff282d9a5f1eaa7426b276bbd3140b61f',
 'sdk-bundles-v2.json': '70626262730fd4e057fb49aa5a404268f8e8192d6b1d3b0f460d3eb5c4a63a05',
 'bundles.json':        'bd530228cb9880d33f49016ab85f426a6c0e9668f3b6e47734b4aa779a71c4fc',
}
FIXURL = 'https://raw.githubusercontent.com/stafordtituss/amep/main/packages/conformance/test/fixtures/ap2/'


def ensure_fixtures():
    """fixtures 优先本地 ../fixtures；缺失则按 pin 下载并逐字节验 SHA"""
    import os, urllib.request, hashlib
    fixdir = os.environ.get('AP2_FIXTURES', os.path.join(os.path.dirname(__file__), '..', 'fixtures'))
    os.makedirs(fixdir, exist_ok=True)
    for f, pin in PINS.items():
        p = os.path.join(fixdir, f)
        if not os.path.exists(p) or hashlib.sha256(open(p, 'rb').read()).hexdigest() != pin:
            raw = urllib.request.urlopen(FIXURL + f, timeout=60).read()
            assert hashlib.sha256(raw).hexdigest() == pin, f'{f} PIN mismatch'
            open(p, 'wb').write(raw)


ensure_fixtures()
VALID_STATUS = {'Success', 'Error'}


def load(f):
    return json.load(open('../fixtures/' + f))


def pick_jwk(trust, kid):
    for name, jwk in trust.items():
        if jwk.get('kid') == kid:
            return jwk
    return None


def verify_jwt_anykey(trust, si, sig):
    """kid 不在 trust 时兜底：逐把钥匙试验（重算判定，任一通过即真）。
    返回 (ok, kid) —— kid=验过它的钥匙名"""
    for name, jwk in trust.items():
        try:
            if verify_es256(jwk, si, sig):
                return True, jwk.get('kid')
        except Exception:
            continue
    return False, None


def split_blocks(chain):
    """链 → SD-JWT(+KB) 块列表。块 = {jwt, pre_discs, kb, post_discs}
    一个语义单元：issuer jwt + 其披露 + kb-jwt + kb 后披露（closed mandate）。
    空段只作视觉分隔，kb 归属前一个有 jwt 的块。"""
    segs = chain.split('~')
    blocks, cur = [], {'jwt': None, 'kb': None, 'pre': [], 'post': []}
    for s in segs:
        if not s:
            continue
        if s.startswith('Wy'):
            (cur['post'] if cur['kb'] else cur['pre']).append(s)
        else:
            h = json.loads(b64u_dec(s.split('.')[0]))
            if h.get('typ') == 'kb+sd-jwt' and cur['jwt'] is not None and cur['kb'] is None:
                cur['kb'] = s
            else:
                if cur['jwt'] is not None or cur['kb'] is not None:
                    blocks.append(cur)
                cur = {'jwt': s, 'kb': None, 'pre': [], 'post': []}
    if cur['jwt'] is not None or cur['kb'] is not None:
        blocks.append(cur)
    return segs, blocks


def verify_block(block, trust, errs):
    """验一个 SD-JWT(+KB) 块：签名、递归披露解析、sd_hash、cnf 委托绑定"""
    out = {'mandates': [], 'disclosures': [], 'kb': None}
    if block['jwt'] is None:
        return out
    h, p, si, sig = jwt_parse(block['jwt'])
    jwk = pick_jwk(trust, h.get('kid'))
    if jwk is not None:
        if not verify_es256(jwk, si, sig):
            errs.append(f'issuer signature fails (kid={h.get("kid")})')
    else:
        ok, verified_kid = verify_jwt_anykey(trust, si, sig)
        if not ok:
            errs.append(f'issuer signature fails (kid={h.get("kid")}, no trust key matches)')
    res = resolve_block(p, block['pre'])
    if res['digests_missing']:
        errs.append(f'{len(res["digests_missing"])} referenced digest(s) with no committed disclosure (altered presented evidence)')
    if res['digests_unmatched']:
        errs.append(f'{len(res["digests_unmatched"])} disclosure(s) not committed by signed payload or resolved disclosures')
    for d in block['pre'] + block['post']:
        salt, key, val = resolve_disclosure(d)
        if isinstance(val, dict) and 'vct' in val:
            out['mandates'].append(val)
        out['disclosures'].append((key, val))
    if block['kb'] is not None:
        h2, p2, si2, sig2 = jwt_parse(block['kb'])
        cnf = None
        for mm in out['mandates']:
            if isinstance(mm.get('cnf'), dict) and 'jwk' in mm['cnf']:
                cnf = mm['cnf']['jwk']; break
        if cnf is None:
            errs.append('no cnf agent key in open mandate — delegation unverifiable')
        elif not verify_es256(cnf, si2, sig2):
            errs.append('agent (kb) signature fails')
        pre = block['jwt'] + '~' + ('~'.join(block['pre']) + '~' if block['pre'] else '')
        if 'issuer_jwt_hash' in p2 and 'sd_hash' not in p2:
            # 变体绑定：kb 只承诺 issuer JWT（逐披露 digest 仍锚定声明集）
            got = b64u_enc(hashlib.sha256(block['jwt'].encode('ascii')).digest())
            if p2['issuer_jwt_hash'] != got:
                errs.append('kb issuer_jwt_hash does not recompute against issuer JWT')
            else:
                out['binding_variant'] = 'issuer_jwt_hash'
        elif not kb_sd_hash(p2, pre):
            errs.append('kb sd_hash does not recompute')
        kres = resolve_block(p2, block['post'])
        if kres['digests_missing']:
            errs.append(f'kb: {len(kres["digests_missing"])} referenced digest(s) with no committed disclosure')
        if kres['digests_unmatched']:
            errs.append(f'kb: {len(kres["digests_unmatched"])} disclosure(s) not committed by kb payload')
        out['kb'] = {'payload': p2, 'seg': block['kb'], 'iat': p2.get('iat'),
                     'mandates': [v for d in block['post'] for v in [resolve_disclosure(d)[2]]
                                  if isinstance(v, dict) and 'vct' in v]}
    return out


def get(mandates, vct):
    for m in mandates:
        if m.get('vct') == vct:
            return m
    return None


def judge_bundle(fx_name, name, b, trust, row_ref_map):
    """一行 = 一条链（一次支付出示）。返回 rows[]"""
    errs0 = []
    rows = []
    seen_txn = {}   # txn_id -> 第一条的判定上下文
    spend_ok = []   # 已确立 Success 的金额（分）
    unknown_pred = False
    for ci, chain in enumerate(b.get('chains', [])):
        errs = []
        segs, blocks = split_blocks(chain)
        rec = verify_block(blocks[0], trust, errs) if blocks else {'mandates': [], 'disclosures': []}
        open_m = get(rec.get('mandates', []), 'mandate.payment.open.1')
        closed_m = get(rec.get('mandates', []), 'mandate.payment.1')
        if open_m is None:
            errs.append('open payment mandate not resolvable')
        if closed_m is None:
            errs.append('closed payment mandate not resolvable')
        txn = (closed_m or {}).get('transaction_id')
        amt = ((closed_m or {}).get('payment_amount') or {}).get('amount')

        # v2: checkout 绑定（conditional_transaction_id == checkout kb sd_hash；checkout_hash == txn）
        checkout_info = {'presented': bool(b.get('checkouts'))}
        if fx_name == 'sdk-bundles-v2.json' and open_m:
            cond = None
            for c in open_m.get('constraints', []):
                if c.get('type') == 'payment.reference':
                    cond = c.get('conditional_transaction_id')
            if not b.get('checkouts'):
                errs.append('conditional binding unverifiable: checkout absent from presented set')
                checkout_info['presented'] = False
            else:
                co = b['checkouts'][ci] if ci < len(b['checkouts']) else b['checkouts'][0]
                _, cblks = split_blocks(co)
                cerrs = []
                cinfo = verify_block(cblks[0], trust, cerrs) if cblks else {}
                errs.extend('checkout: ' + e for e in cerrs)
                ckb = cinfo.get('kb')
                if ckb and cond is None:
                    errs.append('open mandate lacks payment.reference conditional (schema: contains_unsatisfied)')
                elif ckb and ckb['payload'].get('sd_hash') != cond:
                    errs.append('conditional_transaction_id does not match checkout presentation sd_hash')
                else:
                    checkout_info['conditional_binding'] = True
                # checkout_hash == transaction_id（payment ↔ checkout join key）
                cclose = get(cinfo.get('mandates', []), 'mandate.checkout.1')
                if cclose and txn:
                    if cclose.get('checkout_hash') != txn:
                        errs.append('checkout_hash does not equal payment transaction_id (join key broken)')
                    checkout_info['checkout_hash_matches'] = cclose.get('checkout_hash') == txn

        # receipt：全局按 reference=sha256(kb_seg) 匹配（不假设位置顺序）
        kb_seg = rec.get('kb', {}).get('seg')
        r = row_ref_map.get(kb_seg) if kb_seg else None
        receipt_out = None
        if r is None:
            errs.append('no receipt bound to this presentation (reference rule)')
            receipt_out = {'bound': False}
        else:
            rh, rp, rsi, rsig = jwt_parse(r['raw'])
            if not verify_es256(trust['processorJwk'], rsi, rsig):
                errs.append('receipt signature fails')
                receipt_out = {'bound': True, 'verified': False}
            else:
                receipt_out = {'bound': True, 'verified': True, 'payload': rp}
                st = rp.get('status')
                if st not in VALID_STATUS:
                    errs.append(f'receipt status "{st}" outside enum {sorted(VALID_STATUS)} — unresolved, never promoted')
                    receipt_out['status_valid'] = False
                else:
                    receipt_out['status_valid'] = True

        # 决策层（跨链累计）
        verdict, departed, missing = None, None, None
        hard = [e for e in errs if any(k in e for k in ('digest', 'signature', 'sd_hash', 'replay', 'budget', 'payee', 'amount_range', 'not committed', 'expired'))]
        soft = [e for e in errs if e not in hard]

        replay = False
        if txn and open_m:
            exp, iat = open_m.get('exp'), open_m.get('iat')
            hop_iat = rec.get('kb', {}).get('iat')
            if exp and hop_iat and hop_iat > exp:
                errs.append(f'open mandate expired at hop iat ({hop_iat} > {exp})')
                hard.append(errs[-1])
            if txn in seen_txn:
                replay = True
                hard.append(f'closed mandate {txn} replayed (byte-equal transaction_id presented twice)')
        if open_m and closed_m:
            for c in open_m.get('constraints', []):
                t = c.get('type')
                if t == 'payment.amount_range' and amt is not None:
                    if amt > c.get('max', 10**12):
                        hard.append(f'amount {amt} exceeds amount_range max {c["max"]}')
                if t == 'payment.allowed_payees':
                    # 名单两条来源：① constraint 内联完整对象（synthetic 家族）
                    # ② 独立对象披露（sdk 家族 merchant_1 形态）；vct 对象整体披露不算成员
                    # （closed mandate 的 payee 嵌在 vct 对象内，绝不混入名单——防自证循环）
                    allowed_ids = set()
                    for a in (c.get('allowed') or []):
                        if isinstance(a, dict) and a.get('id'):
                            allowed_ids.add(a['id'])
                    list_established = bool(allowed_ids)
                    for key, val in rec.get('disclosures', []):
                        if (isinstance(val, dict) and 'vct' not in val
                                and val.get('id') and 'name' in val):
                            allowed_ids.add(val['id'])
                            list_established = True
                    payee_id = ((closed_m or {}).get('payee') or {}).get('id')
                    if payee_id and list_established and payee_id not in allowed_ids:
                        hard.append(f'payee {payee_id} not in allowed list')
                    elif payee_id and not list_established:
                        # 2026-11-25 s3 误判根因：名单无法建立曾被静默跳过=当无约束。
                        # 未知是 held（unresolved），不是 no-constraint。
                        soft.append('allowed_payees constraint present but list not resolvable — held, not skipped')
                if t == 'payment.budget':
                    pass  # 预算在行尾统一累计判

        if receipt_out.get('verified') and receipt_out.get('status_valid'):
            st = receipt_out['payload'].get('status')
            if st == 'Error':
                receipt_out['processor_outcome'] = 'Error'
        # 预算判：仅对已确立的 Success 累计；有未知前驱 → unresolved（A2 held-not-dropped）
        budget_note = None
        if open_m:
            for c in open_m.get('constraints', []):
                if c.get('type') == 'payment.budget':
                    bmax = c.get('max')
                    this_row = amt or 0
                    row_success = (receipt_out.get('verified') and receipt_out.get('status_valid')
                                   and receipt_out['payload'].get('status') == 'Success')
                    eff = (sum(spend_ok) + (this_row if (row_success and not replay) else 0)) / 100.0
                    if unknown_pred:
                        soft.append('budget cannot be established: predecessor payment outcome unknown (held, not dropped)')
                        budget_note = f'indeterminate: unknown predecessor; budget.max={bmax}'
                    elif not replay and eff > bmax:
                        hard.append(f'cumulative spend {eff:.2f} exceeds budget max {bmax}')
                    budget_note = f'budget.max={bmax} (major units); effective cumulative spend={eff:.2f}'
        # 累计登记在预算判之后（避免双计）
        if receipt_out.get('verified') and receipt_out.get('status_valid') and receipt_out['payload'].get('status') == 'Success' and not replay:
            spend_ok.append(amt or 0)

        if hard:
            verdict, departed = 'violated', '; '.join(hard)
        elif any('unresolved' in e or 'absent' in e or 'unknown' in e or 'no receipt bound' in e for e in soft):
            verdict = 'unresolved'
            missing = '; '.join(soft)
        elif errs:
            verdict = 'unresolved'
            missing = '; '.join(errs)
        else:
            verdict = 'verified'

        if verdict == 'unresolved':
            unknown_pred = True   # 后续预算不可确立（A2：held-not-dropped）
        rows.append({
            'bundle': name, 'chain': ci, 'transaction_id': txn,
            'amount_as_presented': (f'{amt/100:.2f}' if amt is not None else None),
            'ccs': verdict,
            'departed': departed, 'missing': missing,
            'receipt': {k: v for k, v in receipt_out.items() if k != 'payload'},
            'receipt_status': (receipt_out.get('payload') or {}).get('status'),
            'checkout': checkout_info if fx_name == 'sdk-bundles-v2.json' else None,
            'budget_note': budget_note,
            'checks_seen': sorted(set(e.split(' (')[0] for e in errs)) or ['all recomputations pass'],
        })
        seen_txn[txn] = rows[-1]
    return rows


def build_reference_map(b):
    """全 bundle 收据按 reference=sha256(kb_seg) 归位（join key）"""
    m = {}
    for r in b.get('receipts', []):
        ref = jwt_parse(r)[1].get('reference')
        m.setdefault(('ref', ref), []).append(r)
    out = {}
    for c in b.get('chains', []):
        _, blocks = split_blocks(c)
        kb = blocks[0].get('kb') if blocks else None
        if not kb:
            continue
        ref = b64u_enc(hashlib.sha256(kb.encode()).digest())
        cands = m.get(('ref', ref), [])
        if cands:
            out[kb] = {'raw': cands.pop(0), 'reference': ref}
    # 剩余未匹配的收据（绑定到不存在的出示 → s7 类）
    out['_orphan'] = [r for rs in m.values() for r in rs]
    return out


def main():
    families = {}
    self_checks = []
    for fx in FIX:
        data = load(fx)
        trust = data['trust']
        fam_rows = []
        for name, b in (data.get('bundles') or data).items():
            if not isinstance(b, dict) or 'chains' not in b:
                continue
            refmap = build_reference_map(b)
            fam_rows += judge_bundle(fx, name, b, trust, refmap)
            orphan = refmap.get('_orphan', [])
            if orphan:
                fam_rows.append({'bundle': name, 'chain': None, 'transaction_id': None,
                                 'ccs': 'unresolved',
                                 'missing': f'{len(orphan)} receipt(s) bound to no presented payment in this bundle (orphan)',
                                 'orphan_receipt': True})
        families[fx] = fam_rows

    # 自检（achieved 纪律）：设计的负向 fixture 必须被抓住
    def row_of(bundle):
        for fx, rows in families.items():
            for r in rows:
                if r['bundle'] == bundle:
                    return r
        return None
    EXPECT = {
        'sdk-issuer-jwt-hash': 'verified',  # issuer_jwt_hash 变体绑定（issuer JWT 承诺），非篡改
        'sdk-over-range': 'violated',
        'sdk-wrong-payee': 'violated',
        'sdk-redeemed-twice': 'violated',
        'sdk-declined': 'verified',          # 记录完整真 signed，processor 报 Error（有名字）
        'sdk-lost-receipt': 'unresolved',
        'sdk-budget': 'violated',            # txn-2 累计越界（取 bundle 内最严判定）
        's7-receipt-for-another-mandate': 'unresolved',
        's8-altered-amount': 'violated',
        's10-redeemed-twice': 'violated',
        's11-redeemed-twice-small': 'violated',
    }
    for bundle, expect in EXPECT.items():
        rows = [r for fx, rows_ in families.items() for r in rows_ if r['bundle'] == bundle and r.get('chain') is not None]
        got = 'violated' if any(r['ccs'] == 'violated' for r in rows) else (
              'unresolved' if any(r['ccs'] == 'unresolved' for r in rows) else 'verified')
        self_checks.append({'bundle': bundle, 'expect_contains': expect, 'got': got,
                            'achieved': (got == expect) or (expect == 'violated' and got == 'violated')})

    # 关系级断言（2026-11-25 nmatt1 复核抓出 s3 误判后追加——行级自检是循环论证，关系级才算对照）
    # R1 跨家族一致性：同一语义（wrong-payee）在两个家族必须同判 violated
    def got_of(bundle):
        rows = [r for fx, rows_ in families.items() for r in rows_ if r['bundle'] == bundle and r.get('chain') is not None]
        return 'violated' if any(r['ccs'] == 'violated' for r in rows) else (
               'unresolved' if any(r['ccs'] == 'unresolved' for r in rows) else 'verified')
    g_sdk, g_s3 = got_of('sdk-wrong-payee'), got_of('s3-wrong-payee')
    self_checks.append({'bundle': 'sdk-wrong-payee vs s3-wrong-payee',
                        'expect_contains': 'both-violated',
                        'got': f'{g_sdk} vs {g_s3}',
                        'achieved': g_sdk == 'violated' and g_s3 == 'violated'})
    # R2 fixture 名字方向断言：设计名含失败词的行不得为 verified
    # （redeemed-twice 的首呈现 verified 是设计行为——重放判在第二次出现，见 dictionary；
    #   wrong-/altered 类名字行 verified 则必为误判）
    FAILWORDS = ('wrong-', 'altered')
    bad = [r['bundle'] for fx, rows_ in families.items() for r in rows_
           if r.get('chain') is not None and r['ccs'] == 'verified'
           and any(w in r['bundle'] for w in FAILWORDS)]
    self_checks.append({'bundle': 'all-rows-name-direction',
                        'expect_contains': 'no-fail-named-row-verified',
                        'got': ('clean' if not bad else 'FAIL:' + ','.join(bad)),
                        'achieved': not bad})

    counts = {}
    for fx, rows in families.items():
        for r in rows:
            counts[r['ccs']] = counts.get(r['ccs'], 0) + 1

    out = {
        'format': 'ccs-column/1.0',
        'joined': '2026-11-25',
        'for': 'google-agentic-commerce/AP2#402 crosswalk',
        'judged_by': 'Correctover receipt-layer (independent CCS replay), Guigui Wang <wangguigui@correctover.com> — IETF draft-correctover-ccs rev10',
        'object_of_judgment': 'the receipt layer and every digest binding: signatures, disclosure digests, kb sd_hash, receipt.reference join, conditional checkout bindings, cumulative constraints — recomputed, not trusted',
        'inputs': {f: {'note': 'fetched from stafordtituss/amep packages/conformance/test/fixtures/ap2/',
                       'sha256': hashlib.sha256(open('../fixtures/' + f, 'rb').read()).hexdigest()} for f in FIX},
        'method': ('independent implementation (sdjwt.py + column.py, python3/cryptography): SD-JWT disclosures resolved, '
                   'all ES256 signatures recomputed (issuer=userJwk, agent=cnf.jwk of open mandate, checkout kb=checkout cnf, receipts=processorJwk), '
                   'every disclosure digest and kb sd_hash recomputed, receipts joined to presentations by recomputed reference=sha256(kb-jwt) '
                   '(no positional assumption), v2 conditional bindings rechecked (conditional_transaction_id==checkout kb sd_hash; checkout_hash==transaction_id), '
                   'constraints evaluated cumulatively across the bundle; budget.max read in major units, amounts in minor units '
                   '(anchored by amount_range conformance); unknown outcomes held as named unresolved, never promoted'),
        'dictionary': ['verified', 'violated', 'unresolved'],
        'definitions': {
            'verified': 'every recomputation passes and all constraints hold for this presentation',
            'violated': 'a hard failure with the departure named: signature/digest/sd_hash/reference binding invalid, constraint breached, or closed mandate replayed',
            'unresolved': 'the presented set cannot establish the outcome: receipt absent or bound elsewhere, status outside enum, predecessor unknown — held as a named state',
        },
        'gaps_printed_as_gaps': [
            'payment_receipt carries no amount field: the settled value is not establishable from these artifacts (issuance property of the schema, shared boundary)',
            'allowed_payees constraint carries digest-only entries; payee judgment relies on disclosed merchant objects within the same bundle',
        ],
        'counts': counts,
        'self_checks': self_checks,
        'rows': {fx: fam for fx, fam in families.items()},
    }
    json.dump(out, open('ccs-column.json', 'w'), indent=1, ensure_ascii=False)
    ok = all(c['achieved'] for c in self_checks)
    print(json.dumps({'counts': counts, 'self_checks': self_checks, 'all_achieved': ok}, indent=1, ensure_ascii=False))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
