# Azure VM migration pre-assessment blocker playbook

Use this playbook only to interpret AzVMTools preflight results. It does not
authorize remediation or migration.

## Required report conclusion

Every assessment report must state:

> No migration actions were performed.

## Blocker categories

### Assessment incomplete

Typical text:

- Deep guest validation was not completed
- `NoPowerStateChanges` was requested
- guest Run Command failed
- OS image compatibility could not be determined

Plan:

1. Keep the VM out of the approved migration scope.
2. Assign an owner to start the VM through normal operations if required.
3. Rerun Deep preflight.
4. Do not reinterpret an incomplete result as GO.

### Resource locks

Typical text:

- `CanNotDelete`
- `ReadOnly`
- resource lock blocks delete/recreate

Plan:

1. Record the exact lock and scope.
2. Obtain approval to remove it only for the change.
3. Define who restores it after validation.
4. Rerun preflight after the lock plan is approved.

### Azure Disk Encryption

Typical text:

- ADE extension present
- encryption settings incompatible with NVMe

Plan:

1. Confirm encryption ownership and regulatory requirements.
2. Follow supported ADE removal or migration guidance.
3. Validate disk encryption state before rerunning preflight.

### SKU, zone, or allocation

Typical text:

- target SKU unavailable or restricted
- target zone unsupported
- `AllocationFailed`
- overconstrained allocation

Plan:

1. Validate the exact SKU and zone in the target subscription.
2. Review PPG, VMSS Flex, networking, and capacity constraints together.
3. Select an approved alternative SKU/zone or schedule a retry window.
4. Treat successful preflight as planning evidence, not a capacity reservation.

### Quota

Typical text:

- family quota insufficient
- regional vCPU quota insufficient

Plan:

1. Record current use, limit, and net vCPU requirement.
2. Request quota in the exact region and VM family.
3. Reassess the complete batch after approval because aggregate demand matters.

### Hyper-V generation or Trusted Launch

Typical text:

- source generation unsupported by target
- Gen1/Gen2 mismatch
- Trusted Launch conversion required

Plan:

1. Confirm guest and image support.
2. Document that Trusted Launch conversion is treated as irreversible.
3. Validate recovery from snapshots before the change.

### NVMe guest support

Typical text:

- unsupported Windows/Linux version
- `stornvme` readiness warning
- StartOverride present
- image NVMe compatibility unknown

Plan:

1. Validate the guest version against Azure NVMe support documentation.
2. Confirm boot-driver preparation is supported.
3. Keep unknown or unsupported guests out of scope.

### Local ephemeral storage

Typical text:

- local storage removed or type changed
- multiple NVMe devices
- SingleDisk leaves capacity unused
- Stripe has zero redundancy

Plan:

1. Inventory pagefile, swap, tempdb, scratch, cache, and application paths.
2. Confirm that no persistent data depends on the local disk.
3. Select `SingleDisk` or explicit zero-redundancy `Stripe`.
4. Record drive-letter and allocation-unit requirements.

### Networking and VNet migration

Typical text:

- target subnet invalid, delegated, reserved, or full
- multiple NICs or IP configurations
- load-balancer membership not copied
- NIC NSG/public IP not copied
- private IP will change

Plan:

1. Record source and target VNet/subnet.
2. Assign DNS, firewall, load balancer, public IP, and monitoring updates.
3. Validate target-subnet NSG behavior.
4. Treat multi-NIC/IP configurations as manual migrations.

### PPG or VMSS Flex

Typical text:

- PPG mismatch
- VMSS zone mismatch
- orchestration mode mismatch

Plan:

1. Confirm desired PPG and VMSS Flex association.
2. Verify zone compatibility and capacity constraints.
3. Do not delete or recreate shared placement resources without impact review.

### SQL Server and tempdb

Typical text:

- SQL Server detected
- tempdb on non-system storage
- automatic SQL startup can race ephemeral disk provisioning

Plan:

1. Keep SQL changes separate from the VM migration.
2. Define tempdb destination and SQL service startup ordering.
3. Include named instances and service accounts.
4. Test service recovery after deallocate/start.

### Marketplace virtual appliance

AzVMTools preserves Marketplace plan metadata, but Marketplace virtual
appliances are not validated.

Plan:

1. Obtain vendor support guidance.
2. Test a disposable clone.
3. Validate NIC ordering, licensing, health probes, routes, and recovery.
4. Exclude the appliance until the vendor-specific plan is approved.

## Scoped change-plan format

For each VM include:

- preflight status
- blocker category
- evidence, sanitized
- prerequisite action
- owner
- validation required
- include/exclude decision

Finish with:

- GO count
- NO-GO count
- incomplete-assessment count
- proposed change-window scope
- explicit statement that no migration actions were performed
