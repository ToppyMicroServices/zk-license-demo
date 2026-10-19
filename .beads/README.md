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
```

The initial backlog covers Windows validation, repeated performance measurements,
an optional independent review, the prepared LinkedIn post and public-response
evaluation. Real-licence and identity integration preparation is tracked
separately; local fixtures do not establish live provider or real-card support.
Publication tasks retain their text and destination approval gates.

Beads was initialized with version 1.1.2, without installing Git hooks or changing
agent instructions. A Dolt remote was configured by initialization; its presence
alone does not mean that the database has been pushed or synchronized.
