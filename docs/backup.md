# Backing up and restoring

AgentGov keeps what it knows in its database: the registry, the evidence ledger, issues
and issues, tickets, approvals. A few things live outside it: the ledger's archives, the
credentials and keys, Keycloak's own database, and the ledger's head kept apart so that a
restore shows. This page says what to back up, how to restore, and what to check after.

## What to back up

| What | Where | How | Restored with the database? |
|---|---|---|---|
| AgentGov's database | PostgreSQL (`AGENTGOV_DATABASE_URL`) | `pg_dump`, or your managed database's backups with point-in-time recovery | — |
| Keycloak's database: agents' OAuth clients and secrets, the realm | Keycloak's PostgreSQL database (in the Compose stack, `keycloak` on the same server) | `pg_dump`, at the same time as AgentGov's | Yes: they belong together |
| The ledger's archives | `AGENTGOV_LEDGER_ARCHIVE_DIR` (a volume, or a bucket mounted as one) | Copy or snapshot it; archives are only ever added | Never older over newer: keep what is there |
| The ledger's head, kept apart | `AGENTGOV_LEDGER_WITNESS_FILE` ([below](#a-rewound-ledger)) | Nothing to back up | **No**: it is what notices that the database went back |
| Credentials and keys | Destinations' and model providers' secret files, the bundle signing key, the transparency log's key, certificates, `AGENTGOV_SIGNING_SECRET`, the admin token, single sign-on's client secret | Your secret store, which backs them up | — |
| Configuration | `.env` and `docker-compose.override.yml`, or the Helm values | With your infrastructure's code | — |
| Caddy's own authority, with `AGENTGOV_CERTIFICATES=internal` ([one server](deploy/server.md#certificates)) | The `caddy-data` volume | Copy it; it changes only when Caddy renews | — |

`agentgov export` writes the registry as manifests ([registry as
code](administration.md#registry-as-code)): a readable copy of what is governed, worth keeping
in Git, but not a backup: it holds neither the ledger nor issues and approvals.

### With Compose

```bash
compose="docker compose -f deploy/compose/docker-compose.yml"
$compose exec -T postgres pg_dump -U agentgov -Fc agentgov > agentgov-$(date +%F).dump
$compose exec -T postgres pg_dump -U agentgov -Fc keycloak > keycloak-$(date +%F).dump
```

Run it from cron, say every night, and keep the files away from the host. Back up before
each upgrade too ([upgrading](deploy/local.md#upgrading)). The [inventory
stack](deploy/local.md#just-the-inventory) has only AgentGov's database:
`docker compose -f deploy/compose/docker-compose.inventory.yml exec -T postgres pg_dump -U
agentgov -Fc agentgov`.

### On Kubernetes

Use the managed database's own backups, with point-in-time recovery: the cloud guides set
them up ([AWS](deploy/aws.md), [Azure](deploy/azure.md), [Google Cloud](deploy/gcp.md)).
Note the time before each upgrade, to restore to it if the upgrade goes wrong. Snapshot the
ledger archive's volume (`controlPlane.ledgerArchive`) on its own schedule.

## Restoring

1. **Stop what writes to the database:** `$compose stop control-plane keycloak`, or scale
   the control plane's Deployment (and Keycloak's) to zero.
2. **Restore it:**

   ```bash
   $compose exec -T postgres pg_restore -U agentgov -d agentgov --clean --if-exists < agentgov-2026-10-12.dump
   $compose exec -T postgres pg_restore -U agentgov -d keycloak --clean --if-exists < keycloak-2026-10-12.dump
   ```

   or restore the managed database to a point in time, as a new server, and point
   `AGENTGOV_DATABASE_URL` (and Keycloak) at it.
3. **Start again:** `$compose up -d --wait`, or scale back up. A backup from an older
   version is brought up to date as the control plane starts (`agentgov db status` says
   where it is).
4. **Check the ledger:** `agentgov ledger verify` (or **Verify chain** under **Ledger**)
   checks that what the database holds is intact. Then **Ledger** says which entries it lost:
   the ones written after the backup. **Accept the restore** there once you know why they
   are missing: AgentGov writes the gap into the ledger (`ledger.rewound`), and the issue
   about it closes. Then make a checkpoint (`agentgov ledger checkpoint`), so that a
   time-stamp vouches for the head the ledger goes on from.
5. **Catch up with what changed since the backup:** agents registered, approved or blocked
   after it, and decisions made since, aren't in the database. Platform syncs read the
   platforms' agents again at their next run; register again what was registered by hand.
   What the lost entries recorded is still in your SIEM, if one received them: the SIEM is
   the record of what happened in between. Tickets opened in a service desk after the
   backup are still there, but AgentGov no longer knows them, and opens new ones for issues
   that are still open ([tickets](tickets.md)).

Test a restore now and then, on a copy: a backup is worth what restoring it shows.

## A rewound ledger

A database restored from an older backup, or rolled back to a point in time, loses the
ledger entries written after it, and the checkpoints that vouch for them, without a trace
in the database itself: its chain still verifies, only shorter. So the control plane keeps
the ledger's head in a file of its own, `AGENTGOV_LEDGER_WITNESS_FILE`, on storage that
restoring the database doesn't touch, and compares the two when it starts and every hour:

* **Entries are missing:** the database's ledger ends before the head in the file.
* **Another history:** the database's entry at that place isn't the one the file names, or
  it is gone and no archive accounts for it: an archive takes an entry only where the chain
  says one did (`ledger.archived`), and only once it is older than the least retention
  period, six months, which the file says (it keeps when that entry was written).

Either is a critical issue (`ledger.rewound`), sent to the default team like any other
([issues](issues.md)); **Ledger** says what is missing, the overview's control plane shows
it, and the EU AI Act report's record-keeping needs attention. The file is left as it is
until an administrator accepts the restore (**Accept the restore** under **Ledger**, or
`POST /v1/ledger/witness/accept`), which writes into the ledger which entries are missing
and when they were written. If nobody restored the database, find out who changed it.

| Where | The file |
|---|---|
| Compose (either stack) | `/var/lib/agentgov/witness/ledger-head.json`, on the `ledger-witness` volume: not PostgreSQL's |
| Helm | On the ledger archive's volume, when `controlPlane.ledgerArchive.enabled` is true (keeping every entry is `retentionDays: 0`) |
| Elsewhere | `AGENTGOV_LEDGER_WITNESS_FILE`, on a volume of its own; `off` keeps none |

The checkpoints' time-stamps and the transparency log show it too, outside AgentGov: a
checkpoint the log holds that the database doesn't was written by a ledger longer than the
one restored ([evidence](evidence.md)).

Without the file, nothing in AgentGov notices a restore, nor entries removed from the end
of the ledger, its head moved back with them; a chain rewritten with every hash worked out
again shows only as checkpoints whose time-stamps vouch from later than their entries.
**Features** → *What AgentGov can reach* says when no file keeps the head.

| Where | How |
|---|---|
| Admin UI | **Ledger**: what is missing, and **Accept the restore**; the overview's *Evidence ledger* |
| CLI | `agentgov ledger witness` (exits with 1 while entries are missing), `agentgov ledger accept-restore` |
| API | `GET /v1/ledger/witness`, `POST /v1/ledger/witness/accept`; `witness` in `GET /v1/overview` |
| In the ledger | `ledger.rewound` (critical): the head the database had, the head AgentGov had kept and when, and the entries missing |
