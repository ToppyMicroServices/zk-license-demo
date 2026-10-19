# 公開デモの反応評価

調査日: 2026-10-19 JST。対象: [ToppyMicroServices/zk-license-demo](https://github.com/ToppyMicroServices/zk-license-demo)。
Beads: `zkl-11v`。

取得できたGitHubの公開記録では、第三者による具体的な技術質問と再現報告は確認されなかった。
READMEのファイルページには1回の閲覧が記録されていたが、読者の属性や流入元は分からない。
今回の結果から、採用やブランド向上の効果は判断できない。

## 観測範囲と結果

Issue・PRは、リポジトリ作成日時の2026-10-04 13:24 UTCから、2026-10-19 12:28 UTCの取得時点までに
残っている公開記録を調べた。継続監視ではなく、初回のスナップショットである。
リポジトリの公開開始日時、過去に削除された記録、Stars・Forksの増減は確認していない。

| 指標 | 観測結果 |
| --- | --- |
| Stars / Forks | 各0（取得時点の現在値） |
| 通常のIssue | 0件 |
| PR | 6件。すべてメンバーによる作成 |
| Issue・PR会話コメント / PR行コメント / PRレビュー | 6件 / 2件 / 2件。すべてBot |
| 第三者による具体的な技術質問 | 確認した公開記録では0件 |
| 第三者による再現報告 | 確認した公開記録では0件 |
| GitHub Discussions | リポジトリで無効 |

Trafficは同日に既存のGitHub CLI認証で取得した。
`views` と `clones` の日別レスポンスには **2026-10-05〜2026-10-18 UTC** の日付が含まれていた。
以下の数値はAPIが返した `count` と `uniques` をそのまま記録したものである。

| Traffic指標 | count | uniques |
| --- | ---: | ---: |
| Repository views | 7 | 2 |
| Clones | 334 | 82 |
| `docs/press-ja.md` のファイルページ | 5 | 2 |
| `README.md` のファイルページ | 1 | 1 |
| `docs/article-ja.md` のファイルページ | 1 | 1 |

ファイル別の3行は `popular/paths` の返却結果である。このAPIは過去14日間の上位コンテンツを返し、
日別の内訳は返さない。READMEの数値は `/blob/main/README.md` の閲覧であり、
リポジトリトップでのREADME表示を含む全読者数や、LinkedInからの遷移数ではない。

GitHubはTrafficをUTCで集計し、clone数はfetchを含まないと説明している。
API仕様はviewsとclonesを過去14日間の値と定義する。
参照: [Traffic API](https://docs.github.com/en/rest/metrics/traffic)、
[Trafficの表示と更新](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-traffic-to-a-repository)。

## 集計方法と限界

[リポジトリAPI](https://api.github.com/repos/ToppyMicroServices/zk-license-demo)、
[全状態のIssue・PR一覧](https://api.github.com/repos/ToppyMicroServices/zk-license-demo/issues?state=all&per_page=100&page=1)、
[会話コメント一覧](https://api.github.com/repos/ToppyMicroServices/zk-license-demo/issues/comments?per_page=100&page=1)、
[PR行コメント一覧](https://api.github.com/repos/ToppyMicroServices/zk-license-demo/pulls/comments?per_page=100&page=1)と、
PR #1〜#6の各 `/reviews` を取得した。各一覧は100件を指定し、返却件数が100件未満であることを確認した。
通常Issueは `pull_request` を持つ記録を除いて数えた。作成者の区分とBot区分を確認し、
開発中のPR、Botレビュー、管理者側のCIを第三者の質問・再現報告から除外した。

Trafficの取得先は同リポジトリの `/traffic/views`、`/traffic/clones`、
`/traffic/popular/paths` である。最初のコネクタ呼び出しではURLの許可範囲外として取得できなかったが、
GitHub CLI経由の読取りで解消した。取得不能を0として集計していない。

Trafficの集計値から、第三者・管理者・人間・自動処理やCIを区別することはできない。
`uniques` を実人数や利用企業数と解釈せず、334 clonesを第三者による334回の再現とは扱わない。
流入元別の評価、公式サイトのアクセス、LinkedInの閲覧・反応は今回未取得であり、0件とはしない。
GitHub外の質問・再現報告も今回の集計対象外である。

評価資料には集計値だけを残し、個人名、アカウント名、メールアドレス、個人を識別するIDは保存していない。
対外投稿、問い合わせ、ローカルでのテスト実行は行っていない。

この記録を初回の基準値とする。今後具体的な質問や再現報告が得られた場合は、その内容と対象版を区別して
集計する。アクセス数だけを技術理解、実利用、ブランド向上の証拠にはしない。
