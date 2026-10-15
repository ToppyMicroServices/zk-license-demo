# Toppy ZK License Demo

**免許証のコピーではなく、必要な条件の証明を受け取る。**

署名付きの架空の資格情報から、属性値を開示せずに条件を証明するサンプルです。
暗号処理は [AnonCreds / anoncreds-rs](https://github.com/anoncreds/anoncreds-rs) を利用します。
独自の暗号方式、新しい本人確認標準、日本の実免許証認証サービスではありません。

> CLI版の検証（2026-10-15）: macOS、Ubuntu 24.04、Windows Server 2022 x64で、
> 全50テスト（非暗号34件・実暗号16件）が通過しました。
> UbuntuとWindowsのCIで、実証明・独立検証・再送拒否も成功しました。
> 3環境で各30回の性能計測を実施しました。詳細は[検証状況](docs/validation.md)と
> [計測結果・範囲](docs/performance.md)を参照してください。

## 何を証明するか

検証者があらかじめ信頼した模擬発行者の署名に対して、同じ資格情報の以下の2条件を証明します。

- `can_drive_ordinary >= 1`。発行者側で値を0または1に制限しています。
- `valid_until >= service_day`。値は実在する日付を正規化したYYYYMMDD整数です。

氏名・住所・生年月日・免許証番号・有効期限の元の値は開示しません。
発行者定義の識別子、証明、要求ID、条件そのものなどは公開されます。
検証者には別途、セッションや一回限りの要求の状態が残ります。

「現在、停止・取消しのない運転免許を持つ本人だ」とは証明しません。
操作している人と名義人の一致、カード現物の所持、失効照会、契約上の本人特定は別問題です。

## 実行

Python 3.12をCIの検証対象として設定しています。ローカルではmacOS / Python 3.14.6で検証しました。
Ubuntu / Python 3.12.15とWindows Server 2022 x64 / Python 3.12.10でもCIを通過しました。
各環境向け公式wheelのハッシュを固定しています。
最初の依存関係取得にはインターネット接続が必要です。CLIは外部通信を行いません。
下記の画面版は同じPCのブラウザとローカルHTTPで通信します。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
REQUIRE_CRYPTO=1 python -W error -m unittest discover -s tests -v
python demo.py run --out artifacts/run
python demo.py verify --out artifacts/run
# 同じ要求の再利用なので、次のコマンドはalready_usedで失敗するのが正しい動作
python demo.py verify --out artifacts/run
```

模擬資格情報の有効期限は2031-12-31、デフォルトの利用予定日は2030-06-01です。
いずれも説明用の日付であり、報道の発生日とは無関係です。
一回限りの要求は生成から300秒で期限切れになります。期限切れになった場合は新しい出力先で`run`し直してください。

WindowsのPowerShellではvenvの有効化に`.venv\Scripts\Activate.ps1`、環境変数設定に
`$env:REQUIRE_CRYPTO="1"`を使用します。

### 模擬ウォレットの画面とAPI

```bash
python service.py
```

表示された`http://127.0.0.1:8765`を開き、端末に出るログインコードを入力します。
要求の相手・目的・条件・期限を確認して、同意するか選べます。
同意後は実AnonCreds証明を生成・検証し、その要求を使用済みにします。
拒否した場合は証明を作りません。コードは模擬アカウントへのアクセス用で、実本人確認ではありません。

認証セッション、CSRF対策、要求との同意の結び付け、JSON API、単一プロセス内のレート制限を実装しています。
発行者・保有者・検証者は同じプロセスで動き、実カードの読取りや状態照会は行いません。
ローカル専用で、本番用HTTPサーバーではありません。
詳しい起動方法・API・制限は[画面版の説明](docs/service.md)、
実連携の利用条件は[調査メモ](docs/real-license-integration.md)を参照してください。

### 繰り返し性能評価

```bash
python benchmark.py --runs 30 --warmups 3 --out artifacts/benchmark.json
```

同じ模擬資格情報から、新しい要求ごとに証明を作成・検証します。
鍵生成・資格情報発行は別に計測し、3回のウォームアップを除いた30回の生データ、
中央値・p95、実行環境とソースのハッシュをJSONに保存します。
各回で再送拒否も確認します。既存の結果ファイルは上書きしません。
これはローカルでの直列計測であり、サービスの負荷試験や本番性能を示すものではありません。

### 出力の読み方

`artifacts/run/report.html`をブラウザで開くと、利用者側の模擬データと、検証者へ渡る項目の説明を確認できます。
このHTMLは実際の証明生成・検証が成功した場合だけ生成します。外部リソースやJavaScriptはありません。

- `proof-envelope.json`: 検証者へ送る証明と要求ID。秘密鍵・元の資格情報は含みません。
- `trust.json`: 検証者側で用意した模擬の信頼設定。**証明提出者が渡した鍵を信頼する仕組みではありません。**
- `verifier-state.sqlite3`: 独立した検証CLI用の、まだ使用されていない要求状態。
- `demo-state.sqlite3`: `run`内で検証済みの状態。再送拒否を確認するためのもの。
- `request.json`: 検証者が作った要求の説明用エクスポート。CLIのセッション値は本人認証の代わりではありません。
- `report.json` / `report.html`: 模擬の個人属性も表示する**説明用レポート**。検証者の保存データとは異なります。

発行者秘密鍵・利用者のlink secret・処理済み資格情報はメモリ内だけに置き、ファイルには保存しません。
ただし、発行・保有・検証を1台で動かす教育用サンプルであり、OS上の隔離や安全なメモリ消去は実装していません。

## Toppyとして示す部分

ZKによる属性の非開示そのものをToppyの発明とは扱いません。
このサンプルの焦点は、実際に公開されるデータ、発行者の信頼設定、条件の弱体化、期限・宛先・セッション・再送の扱いを、
読めるコードと拒否テストで一緒に示すことです。

`tests/test_policy.py`は30件のポリシー・入力・保存状態テストです。
ここで使用するTrue/Falseコールバックは、暗号処理の代わりではなく保存状態の単体テスト用です。
`tests/test_crypto.py`は16件の実AnonCreds統合テストです。署名改ざん、弱い条件への差し替え、
条件の値・属性・演算子の変更、同じ発行者IDを名乗る別鍵、証明改ざん、
独立したプロセスでの検証を含みます。
`tests/test_benchmark.py`の4件は、集計方法と既存結果の保護、失敗時に成功レポートを出さないことを確認します。
`tests/test_service.py`は、実暗号を使う18件のHTTP統合テストです。
認証・セッション間の分離・同意の省略・改ざん・再送・レート制限を検査します。
ローカルソケットを利用できる環境が必要です。

検証前に、証明内の属性名・演算子・閾値が保存した要求と一致することを確認します。
固定したAnonCreds 0.2.3では、要求を渡して暗号検証するだけでは弱い条件の証明を拒否できませんでした。
この照合後も、署名と証明の暗号検証を必ず実行します。

暗号ライブラリがない場合、通常のローカルテストは暗号クラスをskipします。
**CIと公開前確認は`REQUIRE_CRYPTO=1`を設定し、ライブラリがなければ必ず失敗します。**
デモの実行に成功表示だけを返す代替実装はありません。

## 公開

公開コード: [ToppyMicroServices/zk-license-demo](https://github.com/ToppyMicroServices/zk-license-demo)。
一般向けの説明と、カーシェアの情報流出をきっかけとした保持・管理の提案を日英で公開しています。
[日本語記事](https://www.toppymicros.com/zk-license-demo.html) · [English article](https://www.toppymicros.com/zk-license-demo-en.html)
（リポジトリ内の本文: [日本語](docs/press-ja.md) · [English](docs/press-en.md)）。
`publish.sh`は初回公開に使用したスクリプトです。GitHub CLIでの認証と組織への作成権限があり、
同名のリポジトリがまだ存在しない場合に、依存関係を入れて次を実行できます。

```bash
./publish.sh
```

これは全テスト・実証明・独立検証・再送拒否を確認してから、**公開リポジトリを作成してpushする**スクリプトです。
既存のGitリポジトリ内では実行を拒否します。既存のサイトやLinkedInには変更を加えません。
準備時点の検証状況を記録した文書は、そのまま過去の記録として残ります。

[LinkedIn投稿案](docs/linkedin-ja.md)は下書きです。公開条件は[掲載判断メモ](docs/publication-decision.md)を参照してください。

## 対象外

日本の免許証IC/RSA署名を直接検証するアダプター、実カードの読み取り、OCR、本人性・生体認証、
停止・取消し・失効照会、法令上の保存義務の判断、リレー攻撃対策、端末侵害対策は含みません。
匿名性はIPアドレスやアカウント、アクセス時刻などにも影響されます。完全匿名を主張しません。

原本を発行者が最初に確認する工程は消えません。正規の発行者署名と、署名された値の意味への信頼が出発点です。
ZKは流出済み画像の無効化や侵入防止の代替策ではありません。

## 関連資料

- [報道・一次発表・先行技術の確認](docs/sources.md)
- [脅威モデルと責任分界](docs/threat-model.md)
- [記事案](docs/article-ja.md)

残作業はBeadsで管理します。`bd list --limit 0`で一覧を確認できます。
データの扱いは[タスク管理の説明](.beads/README.md)を参照してください。

License: MIT for this sample. The separately installed anoncreds dependency is Apache-2.0.

---

**English summary:** An educational, synthetic-credential demonstration of non-disclosing AnonCreds predicates,
trusted issuer key pinning, and stateful replay rejection. Not a new cryptographic scheme, a Japanese driving
licence reader, or a production identity service. The original 50 CLI tests passed on macOS, Ubuntu 24.04 and
Windows Server 2022 x64 with the real AnonCreds 0.2.3 backend. A [public English article](https://www.toppymicros.com/zk-license-demo-en.html)
explains the proposal and data-retention guidance. The verifier explicitly matches embedded predicates to its stored policy before
cryptographic verification. Ubuntu and Windows CI passed all demo gates. The release gate fails when the actual backend is unavailable.
The local wallet/API adds synthetic-account sessions, request review, explicit consent and rate limits.
It co-locates all roles and does not establish real identity or live driving-entitlement status.
