# Sources and claim boundaries

Checked: 2026-10-04. These references establish context and prior work, not successful execution of this sample.

## Incident context

1. テレビ朝日、2026-10-02 14:03
   「タイムズカー、最大660万件漏洩　免許証画像流出も　信用情報機関に問い合わせ殺到」
   https://news.tv-asahi.co.jp/news_economy/articles/900201014.html
   The news item supplied by the owner. This sample neither reproduces the reported system nor claims that ZK would have prevented its compromise.

2. パーク24、2026-09-29
   「タイムズカーWebシステムへの不正アクセスに関する調査結果および今後の対応について（第3報）」
   https://www.park24.co.jp/news/2026/09/20260929-1.html
   The primary notice reports about 1.6 million **accounts** with leaked identity-document information, including driving-licence images. Do not restate that as exactly 1.6 million licence images or persons.

## Existing technology — not claimed as Toppy inventions

3. AnonCreds specification
   https://anoncreds.github.io/anoncreds-spec/
   Basis for signed attributes, hidden attributes, predicate proofs and presentation nonces.

4. anoncreds-rs and its official Python example
   https://github.com/anoncreds/anoncreds-rs
   https://github.com/anoncreds/anoncreds-rs/blob/main/wrappers/python/demo/test.py
   API source inspected during preparation. The inspected example blob was `14a1f4c157109aff0bd1a82e0a2b55f1bc4635d3`.
   The Python wrapper `types.py` blob inspected was `1205a8d5509187893bcf16881cf365d0eecbc518`.
   Source inspection is NOT execution testing or confirmation of all version compatibility.

5. Official Python distribution, anoncreds 0.2.3
   https://pypi.org/project/anoncreds/
   The retrieved page listed 0.2.3, released 2025-11-13. The four published wheel SHA-256 values are pinned in requirements.txt.

6. Longfellow ZK
   https://github.com/longfellow-zk/longfellow-zk
   The project describes zero-knowledge protocols for existing MDOC, JWT and W3C credential formats.
   This establishes that ZK for existing identity credentials is not a new proposal from this sample.
   Longfellow is not a dependency of this implementation.

7. ZKPassport
   https://zkpassport.id/
   The project's own description covers eligibility checking through on-device proofs derived from signed identity documents.
   Its stated support does not establish support for every Japanese driving licence.
   ZKPassport is not a dependency, and its product claims were not independently audited here.

No survey of the public's awareness was performed. No audience-reach or brand-lift measurement was performed.
