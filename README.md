# Toppy ZK License Demo

**免許証のコピーではなく、必要な条件の証明を受け取る。**

署名付きの架空の資格情報から、属性値を開示せずに条件を証明するサンプルです。
暗号処理は [AnonCreds / anoncreds-rs](https://github.com/anoncreds/anoncreds-rs) を利用します。
独自の暗号方式、新しい本人確認標準、日本の実免許証認証サービスではありません。

> ローカル検証（2026-10-04）: macOS / Python 3.14.6 / AnonCreds 0.2.3で、
> 全46テスト（非暗号30件・実暗号16件）が通過しました。
> 条件を弱めた証明の受理を修正し、条件の書き換えも拒否することを確認しています。
> Ubuntu / Python 3.12.14のGitHub Actionsでも、全46テスト・実証明・独立検証・再送拒否が成功しました。
> 詳細は [検証状況](docs/validation.md)。

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
Linux / Python 3.12.14でもCIを通過しました。Windowsでの実暗号実行は未確認です。
各環境向け公式wheelのハッシュを固定しています。
最初の依存関係取得にはインターネット接続が必要です。サンプル自身は通信を行いません。

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

検証前に、証明内の属性名・演算子・閾値が保存した要求と一致することを確認します。
固定したAnonCreds 0.2.3では、要求を渡して暗号検証するだけでは弱い条件の証明を拒否できませんでした。
この照合後も、署名と証明の暗号検証を必ず実行します。

暗号ライブラリがない場合、通常のローカルテストは暗号クラスをskipします。
**CIと公開前確認は`REQUIRE_CRYPTO=1`を設定し、ライブラリがなければ必ず失敗します。**
デモの実行に成功表示だけを返す代替実装はありません。

## 公開

公開コード: [ToppyMicroServices/zk-license-demo](https://github.com/ToppyMicroServices/zk-license-demo)。
一般向けの説明と、カーシェアの情報流出をきっかけとした保持・管理の提案は[公開説明](docs/press-ja.md)を参照してください。
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

License: MIT for this sample. The separately installed anoncreds dependency is Apache-2.0.

---

**English summary:** An educational, synthetic-credential demonstration of non-disclosing AnonCreds predicates,
trusted issuer key pinning, and stateful replay rejection. Not a new cryptographic scheme, a Japanese driving
licence reader, or a production identity service. All 46 tests passed locally on macOS with the real
AnonCreds 0.2.3 backend. The verifier explicitly matches embedded predicates to its stored policy before
cryptographic verification. Ubuntu / Python 3.12.14 CI also passed all tests and demo gates. The release gate fails when the actual backend is unavailable.
