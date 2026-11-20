#!/usr/bin/env python3
"""验收探针：RSA 签名批量校验与密钥强度审计（6 条契约）。密钥现场生成，纯离线。"""
import sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def api():
    from rsa.audit import audit_signatures
    return audit_signatures

_KEYS = {}

def keypair(bits):
    import rsa
    if bits not in _KEYS:
        _KEYS[bits] = rsa.newkeys(bits)
    return _KEYS[bits]

def record(bits=2048, hash_name="SHA-256", message=b"firmware-v1"):
    import rsa
    pub, priv = keypair(bits)
    sig = rsa.sign(message, priv, hash_name)
    return {"public_key": pub.save_pkcs1().decode(), "message": message.hex(),
            "signature": sig.hex(), "hash": hash_name}

@probe("P01 批量入口与合规签名")
def p01():
    fn = api(); out = fn([record()], min_key_bits=2048)
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for f in ("index", "ok", "reason", "key_bits", "hash", "issues"):
        assert f in item, f"item 缺字段 {f}"
    assert item["ok"] and item["reason"] == "ok", f"合规签名应 ok，实际 {item['reason']}"
    assert item["key_bits"] == 2048 and item["hash"] in ("SHA-256", "sha256")

@probe("P02 密钥过短")
def p02():
    fn = api(); item = fn([record(bits=1024)], min_key_bits=2048).items[0]
    assert item["reason"] == "weak_key", f"应为 weak_key，实际 {item['reason']}"
    assert item["key_bits"] == 1024 and item["ok"] is False

@probe("P03 弱哈希")
def p03():
    fn = api(); item = fn([record(hash_name="MD5")], min_key_bits=2048).items[0]
    assert item["reason"] == "weak_hash", f"应为 weak_hash，实际 {item['reason']}"

@probe("P04 签名不匹配")
def p04():
    fn = api(); rec = record(); rec["message"] = "deadbeef"
    out = fn([rec, record()], min_key_bits=2048)
    assert out.items[0]["reason"] == "invalid_signature", f"应为 invalid_signature，实际 {out.items[0]['reason']}"
    assert out.items[1]["ok"], "坏签名之后应继续"

@probe("P05 结构损坏")
def p05():
    fn = api(); bad = record(); bad["public_key"] = "-----BEGIN RSA PUBLIC KEY-----\nzz\n-----END RSA PUBLIC KEY-----"
    bad_sig = record(); bad_sig["signature"] = "nothex"
    out = fn([bad, bad_sig], min_key_bits=2048)
    assert out.items[0]["reason"] == "malformed", f"坏 PEM 应 malformed，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "malformed", f"坏签名编码应 malformed，实际 {out.items[1]['reason']}"

@probe("P06 统计、空输入与批量性能")
def p06():
    fn = api(); rec = record()
    out = fn([rec, record(bits=1024), "garbage"], min_key_bits=2048)
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("weak_key") == 1 and st["by_reason"].get("malformed") == 1, st["by_reason"]
    empty = fn([]); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    recs = [rec] * 200
    t0 = time.perf_counter(); out2 = fn(recs, min_key_bits=2048); cost = time.perf_counter() - t0
    assert len(out2.items) == 200 and cost < 3.0, f"200 条耗时 {cost:.2f}s 超过 3s"

def main():
    print("=" * 60); print("验收探针：RSA 签名批量校验与密钥强度审计（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
