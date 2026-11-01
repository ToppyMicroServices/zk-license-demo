# ローカル検証記録

2026-11-01、macOS arm64、Go 1.27.3で実施しました。
回路は18,291制約、最大3レコード・8通りの解釈です。
元のチェックアウトは `afcfd74cc1c8f50c6ed689afa5eaa347f66d099a` で、
以下はその上に追加したローカル変更に対する結果です。

[機械可読の記録と各回の計測値](validation/2026-11-01.json)には、
依存バージョン、計測対象のソースSHA-256、実行バイナリのSHA-256、ログのSHA-256も保存しています。
鍵、保有者秘密、証明書そのものはこの記録に含めていません。

## テスト

| 実行した確認 | 結果 |
|---|---|
| `go test -count=1 -json -coverprofile=artifacts/coverage.out ./...` | 7テスト関数、親子の重複を除いた134ケースが成功 |
| 固定seedで生成した期間と、独立した日別オラクルとの比較 | 上記の1テスト内で40組が成功 |
| `go vet ./...` | 成功 |
| `go mod verify` | 全モジュールの取得済み内容を検証 |
| 既存Python回帰テスト | 86件を確認。初回68件成功、HTTPの18件はポート権限制限でエラー。権限調整後、この18件を再実行して全件成功 |

新規テストには、実Groth16証明、回答・質問・鍵・nonce・audienceの差し替え拒否、
不正な証明エンコード、保有者秘密の不一致、経歴改ざん、署名付きでも不正な回路入力、
完全性不足、日付・閾値の境界、重複期間、全8解釈、別プロセスの証明生成・検証が含まれます。

134ケースすべてが個別の実証明生成ではありません。
回路の入力制約は、署名を付け直した不正データを直接witnessへ入れ、
ホスト側の入力検査を迂回しても回路が拒否することを確認しています。
不完全な証拠からNOを作ろうとするケースでは、実際のGroth16証明生成も失敗することを確認しました。
日数の計算は、回路の包含排除、参照実装のソート・統合、日別オラクルの3方式を照合しています。

Goライブラリのstatement coverageは74.3%でした。
CLIはテスト内で別プロセスとしてビルド・実行しているため、その実行はこのcoverageに含まれません。

既存コードの確認には次のコマンドを使いました。

```sh
REQUIRE_CRYPTO=1 .venv/bin/python -W error -m unittest discover -s tests -v
# 初回のPermissionErrorが出たHTTP部分だけを、ループバック通信が可能な実行環境で再試行
REQUIRE_CRYPTO=1 .venv/bin/python -W error -m unittest discover -s tests -p test_service.py -v
```

Pythonは3.14.10でした。ソースの修正を要する回帰エラーは見つかっていません。

## 実証明の計測

テスト終了後、ビルド済みバイナリを新しいプロセスから起動しました。
4例を各3回、計12回の証明生成・検証が成功しています。
ウォームアップは除いていません。各行は3回の中央値です。

| 例 | 生成・入力検査・自己検証 | 独立した検証呼出し | 証明本体 |
|---|---:|---:|---:|
| YES | 178.466 ms | 1.296 ms | 164 bytes |
| NO | 165.432 ms | 1.368 ms | 164 bytes |
| UNDETERMINED：解釈の不一致 | 177.606 ms | 1.409 ms | 164 bytes |
| UNDETERMINED：完全性不足 | 172.786 ms | 2.142 ms | 164 bytes |

回路コンパイルとセットアップは2,085.162 msでした。
回答とBase64証明などを含む整形済みJSON全体は394〜405 bytesです。
このサイズは検証者が別に保持する要求・検証鍵を含みません。

プロセス全体の最大RSSは **88,784,896 bytes（84.67 MiB）**、
経過時間は4.303秒でした。`resource.getrusage(RUSAGE_CHILDREN)` で、
1つの子プロセスを測定しています。セットアップ、発行、12回の証明・検証、
ファイル保存を含み、Goコンパイラは含みません。
`/usr/bin/time -l` はsandbox内の `kern.clockrate` 読取りが拒否されたため、
最大RSSの結果として採用していません。

実際に用いたコマンドは以下です。Pythonのシステム側ランチャーがこの環境で起動しなかったため、
既存のvenvのPythonを使用しました。

```sh
go build -o artifacts/career-zk ./cmd/career-zk
../../.venv/bin/python scripts/measure.py \
  --binary artifacts/career-zk --out artifacts/measured-20261101 --runs 3
```

今回の実行では `GOMODCACHE=/private/tmp/career-zk-gomodcache`、
`GOCACHE=/private/tmp/career-zk-gocache` を指定しました。
8論理CPU、`GOMAXPROCS=8` の共有ローカル環境での少数回の計測です。
サービス負荷試験や本番の性能保証ではありません。

## 保存場所と未確認の範囲

この作業環境に残した生ログは `artifacts/tests.jsonl`、
`artifacts/python-regression.log`、`artifacts/python-http-regression.log` です。
計測時の応答・要求・セットアップ・模擬秘密は `artifacts/measured-20261101/` にあります。
これらはGit対象外で、別の環境では再生成します。

GitHub Actions、Linux・Windows上での実行、本番セットアップ、
独立したセキュリティ監査は未実施です。
外部サービスへの接続や実際の個人情報を使う検証も行っていません。
今回完了した範囲は、署名付き合成データによるローカル研究試作です。
