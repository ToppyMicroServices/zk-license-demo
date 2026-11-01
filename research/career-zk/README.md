# 経歴から条件だけを証明するローカル試作

経歴の原文や各勤務期間を渡さずに、**「指定期間内に、Pythonの本番運用経験がN日以上あるか」**を証明します。
署名付きの架空データを使い、YES・NO・UNDETERMINEDの回答とGroth16証明を生成します。
既存の免許証デモとは独立したGoモジュールです。

[English](README.en.md) · [検証記録](validation.md) · [先行研究と研究課題](research.md)

## 動かす

Go 1.26.8以上が必要です。最初の依存取得だけネットワークを使います。
発行・証明生成・検証はローカルで完結し、APIキーは不要です。

リポジトリのルートから実行します。出力先は毎回、新しい名前にしてください。

```sh
cd research/career-zk
go mod download
go test -count=1 ./...
go vet ./...
mkdir -p artifacts
go build -o artifacts/career-zk ./cmd/career-zk
./artifacts/career-zk demo -out artifacts/demo-1 -runs 3
```

このコマンドで、回路のセットアップ、模擬発行鍵と保有者秘密の生成、署名、
4例の証明生成と検証を実行します。成功時だけ `report.json` を保存します。

| 例 | 経験日数の解釈 | 条件 | 回答 |
|---|---|---|---|
| yes | 121日または151日 | 120日以上 | YES |
| no | 121日または151日、対象期間の完全性を発行者が宣言 | 152日以上 | NO |
| undetermined | 121日または151日 | 140日以上 | UNDETERMINED |
| incomplete | 同じ記録だが完全性の宣言なし | 152日以上 | UNDETERMINED |

証明生成と検証を別プロセスでも実行できます。

```sh
./artifacts/career-zk prove \
  -setup artifacts/demo-1/setup \
  -credential artifacts/demo-1/fixtures/undetermined.credential.private.json \
  -holder artifacts/demo-1/fixtures/holder.private.json \
  -request artifacts/demo-1/fixtures/undetermined.request.json \
  -out artifacts/another.response.json

./artifacts/career-zk verify \
  -vk artifacts/demo-1/setup/verifying.key \
  -request artifacts/demo-1/fixtures/undetermined.request.json \
  -proof artifacts/another.response.json
```

成功時の出力は `{"answer":"UNDETERMINED","verified":true}` です。
検証プロセスに必要なのは、信頼済み検証鍵、検証者自身の要求、受け取った証明の3ファイルだけです。
証明者から渡された要求や検証鍵を、そのまま信頼設定として採用しないでください。

個別に準備する場合は `setup -out artifacts/setup-2`、
`fixtures -vk artifacts/setup-2/verifying.key -out artifacts/fixtures-2` が使えます。
別の条件を試す際は、検証者側で要求の期間・`min_days` を変更し、`NewRequest` で新しいnonceを作成します。
ライブラリの `NewHolder`、`NewIssuer`、`Issue` は模擬データ発行にも使えます。

## 判定のルール

各経歴レコードは、保有者識別子、開始日、終了日、Python使用の真偽、
本番運用への該当性（`yes / no / unknown`）を持ちます。
本番運用が不明なら「該当する／しない」の両方を評価します。
Python使用や日付そのものの曖昧さは、この版では扱いません。

最大3レコードに対し、回路は8通りを固定で列挙します。
確定済みレコードや未使用スロットに対応するビットは同じ解釈を繰り返すだけです。
証明者が解釈一覧を提出する入力はなく、不利な解釈だけを外せません。

- **YES**：すべての解釈でN日以上。十分な肯定証拠があれば、経歴全体の完全性は不要です。
- **NO**：すべての解釈でN日未満で、発行者の完全性宣言が質問の全期間を覆う場合。
- **UNDETERMINED**：解釈によって答えが分かれる場合、またはNOに必要な完全性がない場合。

空の経歴、4件以上、不正な日付、未対応ポリシー、署名不正、証明検証の失敗はエラーです。
失敗をNOやUNDETERMINEDに変換しません。CLIは非ゼロで終了し、`error` を返します。

期間はUTCの日付で **[開始日, 終了日)** とします。終了日は数えません。
質問の終了日は評価日 `as_of` 以下でなければなりません。
日付は2000-01-01からの経過日数0〜65535、Nは1〜65535です。
証明書の有効性は `issued_at <= as_of < expires_at` で確認します。
重複した勤務期間は和集合として数え、同じ日を二重計上しません。

## 証明の中で確認すること

単一の模擬発行者が、件数・全レコード・有効期間・完全性の対象期間・完全性フラグを
まとめたマニフェストに署名します。完全性は、当該保有者のPython本番運用経験について、
指定期間内の関連記録がこのマニフェストにすべて含まれる、という発行者の宣言です。
各レコードの期間は、その宣言の対象期間内に収めます。

回路内でEdDSA署名、全レコードの保有者一致、保有者秘密の知識、日付と値の範囲、
全解釈の日数計算と回答を検査します。ホスト側の署名チェックを飛ばしても、
回路内の検査を通さなければ証明を作れません。
署名には件数とゼロ埋めスロットも含めるため、署名済みマニフェストの途中を削れません。

`subject = MiMC(102, holder_secret)` とし、秘密を知る保有者に証明を結び付けます。
`commitment = MiMC(103, signed_manifest_digest, fresh_blind, request_id)` は毎回乱数で変わります。
要求の固定順JSONをSHA-256でハッシュしてBN254スカラー体に写した `request_id` に、
ポリシー、期間、評価日、N、発行者鍵、検証鍵のハッシュ、audience、nonceを束縛します。
要求ハッシュは検証者が自身の要求から計算します。回路内でSHA-256を実装しているわけではありません。

検証者には回答、質問の内容、発行者公開鍵、検証鍵の識別子、宛先とnonce、
乱数化コミットメント、証明が分かります。
署名、保有者識別子、経歴の各日付、レコード数、完全性フラグは証明の公開入力に含めません。
発行者鍵や質問内容から分かる情報は残ります。公開データと繰り返し質問を組み合わせた推測は防ぎません。

## 信頼と保存

発行者による経歴の事実確認・完全性宣言を信頼します。
ZKはその宣言の真実性や、画面を操作する人の身元を調査しません。
保有者秘密を他人に渡せば、その人も証明を作れます。
複数雇用主の証明書の集約、失効照会、最新版の証明書の選択は未実装です。
実データ、自然言語の履歴書、JPKI、LLMは使用していません。

gnark v0.16.4、Groth16、BN254と回路内EdDSA/MiMCを使用します。
この小さな回路では、署名から回答までを一つの証明で検査できます。
セットアップは実際の乱数で生成しますが、単独のローカル処理です。
セットアップ担当者と生成した検証鍵を信頼する前提があり、本番向けの共同セットアップや独立監査は行っていません。
回路・ポリシーを変えた場合は、新しいセットアップと検証鍵の合意が必要です。
基盤の手順は [gnark公式文書](https://docs.gnark.consensys.com/HowTo/prove)、
固定版は [v0.16.4リリース](https://github.com/Consensys-Incorporated/gnark/releases/tag/v0.16.4)を参照してください。

デモでは発行者秘密と保有者秘密も `*.private.json` に保存します。
生成ファイルは0600、作成ディレクトリは0700で、既存ファイルを上書きしません。
`artifacts/` はGitの対象外です。暗号化保管や自動消去は実装していないので、
検証者への受け渡しには `*.response.json` のみを使い、秘密を含むデモフォルダ全体を共有しないでください。
保存が不要になった模擬秘密は削除できます。再実行には新しいデモ出力先を使います。

`verify` は状態を保存しません。同じ要求と証明をもう一度検証すると再び成功します。
nonceとaudienceの差し替えは拒否しますが、使用済みnonceの記録・同意画面・質問回数制限は未実装です。
これらは実サービスに組み込む際の追加作業です。

## ファイルとテスト

| ファイル | 役割 |
|---|---|
| `circuit.go` | 固定された証明関係と全解釈の列挙 |
| `model.go` | 合成証明書の発行、入力検査、独立した参照計算 |
| `proof.go` | 実セットアップ・証明生成・検証と保存 |
| `files.go` | サイズ制限、曖昧なJSONの拒否、上書き防止 |
| `career_test.go` | 実暗号、回路への不正入力、別プロセス検証、日別オラクル |
| `scripts/measure.py` | コンパイル済みプロセスの時間・最大RSS・ソースハッシュ |

測定する場合は、ビルド後に以下を実行します（macOS / Linux、Python 3）。

```sh
python3 scripts/measure.py --binary artifacts/career-zk \
  --out artifacts/measured-1 --runs 3
```

`report.json` が各回の時間と証明サイズ、`resources.json` がプロセス全体の最大RSSと
ソースのSHA-256を記録します。コンパイラのメモリは含みません。
測定の生データと実施済みテストの範囲は[検証記録](validation.md)を参照してください。
