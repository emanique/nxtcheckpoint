# Read-only NSX identity and realized group inventory

NXTCheckpoint can now query the NSX fabric and Policy APIs to build a restricted **private** workload-to-IP inventory for offline group expression analysis. No Check Point configuration is written or published.

## API endpoints

- `GET /api/v1/fabric/virtual-machines` — VM identifiers
- `GET /api/v1/fabric/vifs` — NIC owner VM IDs and addresses
- `GET /policy/api/v1/infra/domains/{domain}/groups/{group}/members/ip-addresses` — effective group members
- Existing NSX Policy API collector for domain groups and policies

Use the NSX API release documentation to confirm availability, permissions and fields in your installed version. The collector requires read permissions for VM/VIF inventory and group realization.

## Private collection

```bash
export NSX_USER=readonly-account
export NSX_PASSWORD=replace-with-secure-secret
python -m sync_engine.inventory \
  --config /etc/nsxcp/config.yaml \
  --output /secure/private/nsx-inventory-001
```

A new `inventory.private.json` file is created with mode 0600. For safety, the tool refuses to overwrite an existing file. **Do not use a public or Git-tracked output directory.** This file contains real VM IDs, IPs and group membership and therefore is sensitive.

## Freshness-checked private assessment

```bash
python -m sync_engine.offline \
  --input /secure/private/nsx-export.json \
  --inventory-file /secure/private/nsx-inventory-001/inventory.private.json \
  --max-inventory-age-seconds 600 \
  --output /secure/private/assessment
```

The report contains only counters, reason codes and pseudonymous rule identifiers. It does not include original workload names, IPs, source paths or source rule names. It **must not be treated as anonymous against dictionary attacks**, so keep it private.

## Fail-closed checks

- Missing VM external IDs, duplicate IDs and source-invalid VMs
- VIFs lacking VM ownership, IP metadata or trusted `VM_TOOLS` provenance
- Duplicate IPv4 ownership across different workloads
- Orphan VIF owner references not present in the VM inventory
- Missing VMs/VIF inventory
- Failed group membership fetch, schema mismatch or pagination failure
- Inventory older than configured maximum (default 600 s) or dated unexpectedly in the future
- Unsupported group semantics remain blocked by the expression resolver

## Operational limitations

The VIF inventory relies on VM Tools reported addresses, which can be stale or incomplete. The code does not independently prove that all workloads or VIFs have been discovered, that the enforcement point is correct, or that the read-only API result is synchronized with a cutover point-in-time. Group effective IP members are retained for private comparison, but **the tool does not yet reconcile them with resolved expressions**, or automatically attest to rule-order and topology equivalence.

This feature is an assessment input, **not automatic assurance of enforceable Check Point policy**. Deploy with least-privilege credentials and monitoring. Do not put secrets or private exports in GitHub Actions, issues or repository artifacts.

All repository tests use synthetic fixtures and reserved documentation IP ranges.

## Reference
[NSX-T Data Center REST API](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/)
