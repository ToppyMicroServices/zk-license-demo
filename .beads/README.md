# Demo task tracking

Use Beads for work on the existing synthetic demo. The local embedded Dolt
database is the task source of truth. `issues.jsonl` is an exported snapshot for
review and interchange, not a full database backup or proof of remote sync.

```bash
bd list --limit 0
bd show zkl-0z5
bd update <id> --status in_progress
bd close <id> --reason 'Describe the completed checks and evidence'
bd export -o .beads/issues.jsonl
bd dolt commit -m 'chore(tasks): record validation progress'
bd dolt push
```

Commit and push the reviewed JSONL snapshot with Git separately. The Dolt push
stores the full database history under `refs/dolt/data`; a normal Git push of
`issues.jsonl` does not do this. Fresh clones use `bd bootstrap` to adopt the
published database, then `bd dolt pull` before making task updates.

The initial backlog covers Windows validation, repeated performance measurements,
an optional independent review, the prepared LinkedIn post and public-response
evaluation. Real-licence and identity integration preparation is tracked
separately; local fixtures do not establish live provider or real-card support.
Publication tasks retain their text and destination approval gates.

Beads was initialized with version 1.1.2, without installing Git hooks or changing
agent instructions. On 2026-10-25, version 1.3.2 could not read the old schema
(53); its issue queries required the missing `leases` table. The configured
remote had no `refs/dolt/data` yet. After copying the full local `.beads`
directory for recovery, this database was migrated once to schema 66 with
`bd migrate --force --yes`. All 23 issues remained readable. The migrated
database was pushed, the remote ref was confirmed, and `bd dolt pull` succeeded.

Only one designated database should apply a schema migration and publish it.
Other clones must adopt that history rather than independently force-migrating
their old schema. Follow the installed CLI's migration guidance and the
[upstream sync guide](https://github.com/gastownhall/beads/blob/main/docs/getting-started/sync-setup.md).
The JSONL export and local directory backup have different scopes; neither a
configured remote nor a JSONL commit proves that the full database was pushed.
