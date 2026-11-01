# 先行研究と次の研究課題

確認日：2026-11-01。以下は限定した比較であり、網羅的な新規性調査ではありません。
この試作の実装対象は、署名付き経歴、有限の役割解釈、期間の和集合、完全性を要するNOを
一つの固定回路にまとめ、拒否条件を実行可能にすることです。

| 先行研究 | 確認した内容と今回の関係 |
|---|---|
| Damiano Mombelli, [General-Purpose Zero-Knowledge Proofs for Verifiable Credentials](https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/appliedcrypto/education/theses/masters-thesis_damiano-mombelli.pdf), 2025 | 署名付き資格情報に柔軟な検証ロジックを適用し、リンクした資格情報の集計値の性質も証明する。資格情報から計算結果だけを証明するという大枠には先行例がある。 |
| Leonid Libkin, [How to Define Certain Answers](https://ijcai.org/proceedings/2015/609), 2015 | 不完全情報が表す可能な世界に対して、どの解釈でも成り立つ回答を扱う。今回の「全解釈でYES」という意味論は、この既存の考え方に近い。有限列挙自体を新規性とは扱わない。 |
| Breckenridge et al., [πCreds: Privately Inferred Credentials](https://arxiv.org/abs/2606.03771), 2026 | 認証されたデータに対する信頼済みLLM推論から資格情報を作る方式を提案し、入力操作や推論モデルによる漏えいを論じる。今回の試作はLLMを使わず、構造化された役割フラグだけを扱う。確認範囲は要旨。 |
| Jesse Wright, [Towards Provable Provenance and Privacy-Preserving Queries in Decentralised Data Architectures](https://ceur-ws.org/Vol-4085/paper19.pdf), 2025 | SPARQL照会と証明可能な出典・導出を扱い、必要な結果だけを受け取る例を示す。今回の固定質問より広い照会言語を研究対象とする。 |
| Woodruff and Staddon, [Private Inference Control](https://eprint.iacr.org/2004/130), 2004 | 個々の回答が秘密を含まなくても、組合せによる推測が問題になることを扱う。今回のnonce束縛は推測制御ではない。PDF取得は403で失敗したため、確認範囲は公式要旨。 |

この比較から、全解釈での安定性という抽象的な性質そのものを新しい概念として提案する根拠はありません。
署名・完全性・経歴の重複期間を組み合わせた今回の具体的な構成についても、先取性は未確認です。

次に調べるなら、**「役割の曖昧さと署名付きの完全性を扱う際、どの条件なら小さい回路で
正しい三値回答を出せるか」**に絞れます。
現在の質問は単調なので、全8通りを評価した結果は、未知の役割をすべて除いた場合と
すべて含めた場合の両端でも判定できるはずです。これは実装からの推論であり、
この版で両端だけに最適化した回路の証明や計測はしていません。
全列挙版を参照実装として、その最適化の同値性とコストを比較する余地があります。

質問を「期間の重なりが少ない」「複数の役割条件を同時に満たす」などへ広げる場合は、
単調性が維持されるか、完全性の宣言が何を覆うかを先に定義する必要があります。
日付や役割を自然言語からどう確定するかは別の研究課題です。
現実の経歴が正しいことや、すべての自然言語解釈を列挙できたことを、この回路からは結論できません。
