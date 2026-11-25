# CCS 列 × 三方 22 行对拍（2026-11-25）
## 关键读数
- AER-1（记录层）与我们几乎全同（verified 口径），除了：over-range/wrong-payee/budget txn-2/redeemed-twice 它只验记录不判决策 → 我们 violated 是决策层差异（AMEP/APAF1 与我们一致方向）
- sdk-issuer-jwt-hash：AER-1 verified + AMEP preserved + APAF1 approved，唯我们 violated（kb sd_hash 不重算）——需要复查该负向 fixture 的设计意图：它的名字暗示 issuer jwt hash 被改 → 三方都没抓到？还是它设计为"hash 改了但签名仍过"（合法）？必须复查，不能自嗨
- s9 txn-2：AER-1 verified vs 我们 unresolved（预算前驱未知）——决策层差异，与 AMEP/APAF1 (unresolved/escalated) 方向一致
- s3-wrong-payee(synthetic)：AER-1 verified、AMEP violated、我们 violated——注意 synthetic 家族我们判 verified？看输出 s3=verified！→ 需查 synthetic wrong-payee 为何没抓到（payee 披露结构不同？）
## 疑点清单（9+9 前必须清）
1. sdk-issuer-jwt-hash 的设计意图（可能我们过严）
2. synthetic s3 wrong-payee 漏抓
3. s7 我们的 orphan 行 + 链行双 unresolved 的口径
