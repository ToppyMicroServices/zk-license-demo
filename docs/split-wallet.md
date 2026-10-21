# 分離ウォレットと模擬発行鍵のライフサイクル

`split_demo.py` は、発行者・ウォレット・検証者を別のCLIプロセスとSQLiteファイルで動かす。
属性はすべて架空だが、署名、条件証明、失効証明には既存のAnonCreds 0.2.3を使う。
既存の `demo.py` と `service.py` は同一プロセス版として残る。`split_service.py` はウォレットと検証者を別のローカルWebプロセスで動かす。

## 保存と受け渡し

| 領域 | 保持する情報 | 他の役割へ渡すもの |
| --- | --- | --- |
| 発行者 | 発行秘密鍵、失効レジストリ秘密鍵、未使用offer | offer、ブラインド要求に対する資格情報 |
| ウォレット | link secret、資格情報、要求メタデータ、同意履歴 | ブラインド発行要求、同意後の証明 |
| 検証者 | ペアリング秘密鍵、要求、使用済み状態、信頼情報の確認履歴 | HMACで認証した要求 |
| 公開レジストリ | schema、公開鍵、鍵状態、失効リスト、発行番号のカウンタ | 全役割が参照する信頼設定 |

発行者はlink secretを受け取らない。検証者は資格情報やlink secretを開かずに検証する。
公開レジストリと `tails/` は運用者が信頼できる経路で配備する前提で、証明提出者が指定するURLから取得しない。
公開レジストリの更新権限は発行側だけに与える。実際のOS利用者・ACLの設定はこのCLIでは行わない。

初回ペアリングファイルには32バイトのHMAC秘密鍵が入る。運用者が検証者とウォレットの間で安全に渡す。
HMAC-SHA-256は要求の出所と完全性を確認する。人の本人確認、第三者へ示す署名、TLSの代わりではない。
一組の模擬アカウントと端末だけを扱い、複数サービスや実ユーザーの登録は実装していない。

## 実行例

既存のvenvを有効にしたPOSIXシェルで実行する。PowerShellでも同じCLI引数を使えるが、以下の変数・改行はシェルに合わせる。
各出力は新しいファイル名を指定する。要求は300秒で失効する。

```bash
demo_dir=artifacts/split
mkdir -p "$demo_dir/exchange"
python split_demo.py issuer-init --store "$demo_dir/issuer/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --out "$demo_dir/exchange/key.json"
key_id=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$demo_dir/exchange/key.json")

python split_demo.py verifier-init --store "$demo_dir/verifier/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --audience demo.example --out "$demo_dir/exchange/pairing.json"
python split_demo.py wallet-init --store "$demo_dir/wallet/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --input "$demo_dir/exchange/pairing.json"

python split_demo.py issuer-offer --store "$demo_dir/issuer/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --out "$demo_dir/exchange/offer.json"
python split_demo.py wallet-enroll --store "$demo_dir/wallet/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --input "$demo_dir/exchange/offer.json" --out "$demo_dir/exchange/enrollment.json"
python split_demo.py issuer-issue --store "$demo_dir/issuer/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --input "$demo_dir/exchange/enrollment.json" --out "$demo_dir/exchange/credential.json"
python split_demo.py wallet-import --store "$demo_dir/wallet/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --input "$demo_dir/exchange/credential.json"

python split_demo.py verifier-request --store "$demo_dir/verifier/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --key-id "$key_id" --service-day 2030-06-01 --out "$demo_dir/exchange/request.json"
python split_demo.py wallet-review --store "$demo_dir/wallet/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --input "$demo_dir/exchange/request.json" --out "$demo_dir/exchange/review.json"
cat "$demo_dir/exchange/review.json"
```

相手、端末の結び付け、利用日、鍵、開示する値がないこと、期限を確認する。
`review_hash` を確認して、同意する場合だけ次を実行する。
拒否する場合は `--decision deny` にする。拒否はその要求について確定し、証明を生成しない。

```bash
python split_demo.py wallet-decide --store "$demo_dir/wallet/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --input "$demo_dir/exchange/request.json" \
  --review-hash '<確認したreview_hash>' --decision approve --out "$demo_dir/exchange/proof.json"
python split_demo.py verifier-verify --store "$demo_dir/verifier/state.sqlite3" \
  --registry "$demo_dir/public/state.sqlite3" --input "$demo_dir/exchange/proof.json"
```

同意はウォレットのローカル動作として強制する。検証者は同意履歴を受信せず、同意の証拠を検証するわけではない。
資格情報とlink secretを持つ人が別実装で証明を生成することは防げない。
検証者は保存済みの条件、nonce、期限、宛先、ペアリング、現在の信頼情報を使い、成功した要求を一度だけ消費する。
条件を弱めた証明は、従来版と同じ明示的な閾値照合で拒否する。

`verifier-reset` はペアリングを更新して全要求を無効にし、新しいペアリングファイルを `--out` に出す。
ウォレットは `wallet-pair --input <新しいペアリングファイル>` で更新する。古い要求と同意は使えない。
これは実アカウントの移行・復旧ではなく、模擬の端末再登録である。

## 分離したWeb画面

上の初回発行とウォレットへの取込みを終えてから、別々のターミナルで次の2コマンドを実行する。
それぞれのターミナルに異なる模擬ログインコードが表示される。両方のプロセスは同じ公開レジストリを読み、
ウォレットはウォレットDBだけ、検証者は検証者DBだけを開く。発行者の秘密DBはWebプロセスに渡さない。

```bash
python split_service.py --role verifier --store artifacts/split/verifier/state.sqlite3 \
  --registry artifacts/split/public/state.sqlite3 --port 8766 --peer-origin http://127.0.0.1:8767
python split_service.py --role wallet --store artifacts/split/wallet/state.sqlite3 \
  --registry artifacts/split/public/state.sqlite3 --port 8767 --peer-origin http://127.0.0.1:8766
```

ブラウザで `http://127.0.0.1:8766` を開いて検証者のコードでログインし、鍵を選んで要求を作る。
開いたウォレット画面にはウォレット側のコードでログインする。認証済みの要求内容を確認して同意または拒否する。
同意時だけ証明が検証者画面へ渡り、検証者側で条件と模擬失効情報を確認する。
画面間では署名付き要求と同意後の証明だけを、設定された相手のoriginとウィンドウを確認して受け渡す。
各画面のログイントークンはその画面のメモリに置き、Cookieや画面間メッセージには入れない。

発行鍵の更新・個別失効・再発行や `verifier-reset` / `wallet-pair` は上記のCLIで行う。
Webプロセスは起動したまま更新後のDBを読む。検証者画面の鍵一覧は要求作成時に更新する。
再ペアリングや失効の後は古い要求を使わず、新しい要求を作る。画面を再読込みするとログイン状態は失われる。
このWeb版はループバック専用の模擬アカウントで、実本人認証、外部公開用API、実免許証の状態照会は行わない。

## 鍵更新、失効、復旧

発行鍵ごとに別のcredential definitionと失効レジストリを作る。
`issuer-rotate --out <新しい鍵IDファイル>` は新鍵を `active`、旧鍵を `verify_only` にする。
旧資格情報は併存期間に検証できる。新鍵への更新はofferから発行・取込みをやり直す。
属性は模擬の発行側引数から生成し、古い資格情報だけを根拠に再発行しない。

| 操作 | コマンドの追加引数 | 結果 |
| --- | --- | --- |
| 旧鍵へ発行を戻す | `issuer-key --key-id <ID> --action rollback` | 信頼中の鍵だけをactiveに戻す |
| 併存を終了 | `issuer-key --key-id <ID> --action retire` | その鍵の資格情報をすべて拒否 |
| 侵害時の緊急停止 | `issuer-key --key-id <ID> --action revoke` | その鍵の資格情報をすべて拒否 |
| 個別資格情報の失効 | `issuer-revoke --key-id <ID> --index <番号>` | その資格情報の失効証明が検証に失敗 |
| 発行秘密鍵を保存 | `issuer-backup --backup <新しい保存先>` | 秘密情報を含むJSONバックアップ |
| 秘密鍵を復旧 | `issuer-restore --backup <保存先>` | 現在も信頼されている一致する鍵だけを復旧 |

各操作に `--store <発行者DB>` と、backup以外は `--registry <公開DB>` を指定する。
発行番号は鍵ごとに1から増え、試作用レジストリは99件まで発行できる。番号はウォレットの資格情報にはあるが証明で開示しない。
`retired` / `revoked` は終端状態で、rollbackや古いバックアップから有効に戻せない。
侵害鍵を停止した後は `issuer-rotate` で新鍵を作り、新しい資格情報を発行する。

復旧には**生き残った現在の公開レジストリ**が必要である。private DBの紛失からも復旧できる。
公開の失効情報、鍵の停止、番号の割当ては復旧時に戻さない。バックアップにない新鍵は復旧できず、
新鍵生成まで発行を拒否する。公開レジストリまで失った場合の復旧や鍵漏えいの自動検出は扱わない。
秘密鍵と公開状態は、同じローカルディスクのSQLite ATTACH・rollback journalで一緒に更新する。
試験用の書込み条件で、SQL更新後・commit後のプロセス強制終了と明示的なrw接続による復旧を
[Windows／Ubuntuで検証した](issuer-recovery-validation.md)。commit内部の中断、電源断、
ネットワークファイルシステムでの耐障害性、読取り専用の利用側による自動復旧は未検証である。

失効にはAnonCredsのaccumulatorと非失効証明を使う。upstreamの
[Python例](https://github.com/anoncreds/anoncreds-rs/blob/main/wrappers/python/demo/test.py)と同じ
`issuance_by_default=True` を使う。未割当ての番号から証明するにも有効な発行者署名が必要である。
時刻欄には単調増加する模擬の更新番号を使い、壁時計に基づく照会鮮度は示さない。
レジストリの更新が一つでも入ると未完了の要求は無効になり、新しい要求と同意が必要になる。
検証中は公開DBをread transactionで保持し、失効更新のcommitと証明の受入れを直列化する。
すでに受け入れた操作を、後の失効で取り消す仕組みはない。

ウォレットと検証者は、最後に観測した更新番号と内容のハッシュを保存する。
要求を拒否した場合にも新しい観測を残し、古い版や同じ番号の異なる内容を拒否する。
これは新規端末が初めて見る古いレジストリの検出や、全DBを一緒に戻す攻撃への対策にはならない。

## 検証範囲と残作業

`tests/test_split_wallet.py` は実暗号で、別プロセスの受け渡し、同意・要求の改ざん、再送、
再ペアリング、鍵の併存と停止、再発行、個別失効、古いバックアップからの復旧を検査する。
検証者を起動する前に発行者・ウォレットのprivate DBを削除するテストもある。
失効テストではウォレット側の拒否を迂回して本物の証明を生成し、検証者で拒否されることを検査する。
非失効証明を省いて公開識別子だけを付けた証明や、空の非失効証明も拒否し、要求を消費しない。
これは本番セキュリティ監査ではない。

SQLiteと交換ファイルは平文で、POSIXでは新規privateファイルを0600で作る。WindowsのACL、暗号化保存、
Secure Enclave/HSM、OS間の隔離、ファイルの安全な削除、端末侵害への耐性は未実装である。
交換ファイルは自動削除しない。途中の出力書込みに失敗した場合、発行や同意がすでに確定していることがある。
新しいofferまたは要求からやり直す。バックアップ、ペアリング、資格情報ファイルを公開repoへ追加しない。

実カード読取り、実本人認証、警察の停止・取消し照会、インターネット向けAPIは追加していない。
`synthetic_revocation_checked: true` と `live_licence_status_checked: false` を結果に分けて出す。
CLI版の検査とソースのハッシュは[検証記録](split-wallet-validation.json)、分離Webの検査は[別の記録](split-web-validation.md)に保存する。
分離Web画面の作業はBeads `zkl-7al` で追跡し、本番化は `zkl-9w9` に残す。
公開鍵・状態照会の利用条件は[調査メモ](real-license-integration.md)を参照する。
