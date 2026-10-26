# Increment 0 runtime reference

Reference marker: `AZURE-NETWORK-HEALTH-INCREMENT-0-REFERENCE-V1`

The marker is retained for the Increment 0 regression probe. Installed supporting
files, not a GitHub download or developer checkout, must be used at runtime.

## Increment 1 interpretation

The current skill permits only its restricted catalog. Facts/explicit
configuration links belong to observation JSON; interpreted findings belong to
assessment JSON. Configured next hops are not demonstrated packet flow. A
missing property is UNKNOWN, not proof of an absent control.

Severity represents impact; priority represents recommended action ordering.
No customer requirement or architecture standard is invented. Overlap and
disconnected peering require connectivity context. Subnet NSG/route-table
association observations do not establish public reachability or healthy egress.

The default six checks and opt-in checks are versioned in `checks.json`, with precise guidance links.
Microsoft Learn grounding is inherited from Network Desk's validation-first
approach; citations are not proof of live environment behavior. Deep dives are
recommendations only.

Opt-in service access-control evidence covers Storage Accounts, Key Vault vaults
and Container Registries only. Public-access settings, service firewall action,
trusted-service bypass, rule counts and approved scoped PE groups are retained
configuration, not actual reachability or approved exceptions. Disabled is not
a private-only certificate; a perimeter mode is not verified enforcement.
Missing fields never inherit service defaults. Other mapped families remain
explicitly unassessed. See `serviceAccessReview` and the exact executed check
versions, rather than assuming all modes run the same checks.

Opt-in direct ARM reconciliation keeps indexed and management-GET observations
separate. `serviceControlReconciliation` preserves per-field values, actual API
versions, source references and parent read completion/outcomes. Only two
non-null equal values match; unavailable/non-applicable fields and failed reads
are not absence or zero. Differences may reflect source/API/time semantics and
are not automatically defects. Never overwrite an indexed observation with a
direct value, declare either source desired state, or equate matching settings
with effective enforcement, reachability, private-only access or health.

Opt-in NSP review records configured association mode, profile/target references,
provisioning/issue signals and privacy-minimized rule selector counts. Enforced
configuration does not demonstrate effective enforcement or synchronization.
Learning/Transition, Audit, unknown modes and partial parent/rule evidence stay
distinct. Missing arrays are not zero, scoped empty lists do not prove global
absence, external references are not followed and no exception is accepted.
AMPLS, selector values/semantics and active/client behaviour remain unassessed.

Persist only selected evidence. Distinguish artifact creation, byte retrieval and
external publication. This reference contains no customer data or credential.
