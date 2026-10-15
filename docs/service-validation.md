# 模擬ウォレット・APIの検証

2026-10-15時点。実装コミット: `09ee8ba21fda409553a1edda3ee33b6eab400ecf`。
コードと画面のSHA-256は[qa-report.json](evidence/2026-10-15-service/qa-report.json)に記録した。

| 確認対象 | 結果 | 証拠 |
| --- | --- | --- |
| macOS / Python 3.14.6 | 全68テスト成功 | [テストログ](evidence/2026-10-15-service/tests-macos.log) |
| Ubuntu 24.04 / Python 3.12.15 | 全68テスト成功 | [テストログ](evidence/2026-10-15-service/tests-ubuntu.log) |
| Windows Server 2022 / Python 3.12.10 | 全68テスト成功 | [テストログ](evidence/2026-10-15-service/tests-windows.log) |
| macOS内蔵ブラウザ | ログイン、要求確認、同意後の実検証、拒否、ログアウトを操作確認 | [同意画面](evidence/2026-10-15-service/consent.jpg)・[検証結果](evidence/2026-10-15-service/verified.jpg)・[拒否結果](evidence/2026-10-15-service/denied.jpg) |

[CI実行](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/38684849636)では、
全テストのほか、既存CLIの実証明生成・独立プロセス検証・再送拒否・30回の直列計測も成功した。
CIの工程記録と取得したartifactのメタデータも証拠ディレクトリに保存した。
JavaScript構文、公開スクリプトの構文、依存関係の整合、差分の空白検査も通過した。

HTTPテスト18件は、認証・セッション分離・同意省略・要求差し替え・改ざん・再送・
並行再送・期限切れ・入力制限・レート制限を含む。
暗号検証中にセッションが切れるテストも、実暗号検証を実行した後に期限切れを注入し、
成功として要求を消費しないことを確認している。

最初のローカルHTTP試行は、実行環境のサンドボックスがポートの使用を拒否した。
ローカルポート利用を許可された実行で再試験し、上記の結果を得た。
Windows・UbuntuはHTTP自動テストであり、OSごとのブラウザ画面を確認したものではない。
画面の目視確認はmacOSの既定のデスクトップ表示のみ。モバイル、他の表示エンジン、
実カード、JPKI接続、最新の免許状態、本番負荷・運用、独立監査は未検証。
