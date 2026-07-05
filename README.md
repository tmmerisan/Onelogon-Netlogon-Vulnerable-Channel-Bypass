# Onelogon — Netlogon Vulnerable Channel Bypass

*Vulnerability Overview, Exploitation Path & Remediation Guidance*

| | |
|---|---|
| **Type** | Detection & Remediation Guide |
| **Date** | 2026-07-04 |
| **Related** | CVE-2020-1472 (Zerologon) |

---

## 1. Summary

A publicly disclosed technique, referred to as "Onelogon", demonstrates a bypass of the Zerologon (CVE-2020-1472) remediation on Active Directory Domain Controllers. The bypass does not target a new flaw in the Netlogon Remote Protocol (MS-NRPC) itself — it targets legacy compatibility exceptions that administrators may have left enabled after the original Zerologon patch cycle (August 2020 – February 2021).

Where these exceptions are present and misconfigured, an attacker can re-establish an unauthenticated or weakly authenticated Netlogon secure channel, impersonate a computer account, and in some documented cases escalate to full domain compromise (credential dumping via DCSync-style replication, extraction of NTDS.dit).

This does not affect standard, fully patched Domain Controllers with no legacy exceptions configured. Exposure requires a non-default configuration.

## 2. Background: Zerologon (CVE-2020-1472)

Zerologon exploited a cryptographic flaw in the Netlogon session-key negotiation (AES-CFB8 with a static IV), allowing an attacker to authenticate to a Domain Controller as any computer account without credentials, and subsequently reset the machine account password, take over the DC, or extract domain hashes.

Microsoft's fix (rolled out in two phases, Aug 2020 and Feb 2021) enforced secure RPC for all Netlogon connections by default. To avoid breaking legacy/non-Windows devices that could not support secure RPC, Microsoft provided two temporary compatibility mechanisms:

- **Group Policy:** "Domain Controller: Allow vulnerable Netlogon secure channel connections" — lets administrators explicitly allow-list specific accounts to bypass secure RPC enforcement.
- **Registry value** `VulnerableChannelAllowList` under `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` — the underlying mechanism the GPO writes to; can also be set manually.

Both were intended as a short-term bridge, to be removed once legacy devices were upgraded or retired. In practice, many environments configured these during the 2020–2021 rollout under time pressure and never reverted them.

## 3. Exploitation Path (Conceptual)

At a high level, the Onelogon technique works as follows when a vulnerable configuration is present:

- The allow-list (GPO or registry) exempts one or more accounts — sometimes identified by wildcard — from the Zerologon secure-RPC enforcement.
- An attacker with network access to a Domain Controller identifies an exempted account (often a legacy device or a broadly-scoped wildcard entry).
- The attacker establishes a Netlogon secure channel for that account without the modern authentication protections, effectively recreating the original Zerologon impersonation primitive for that scope.
- Depending on the privileges of the impersonated account and domain replication permissions, this can be leveraged to reset computer account passwords, request domain credential replication, or pivot toward full Active Directory compromise.

No exploit code or step-by-step attack procedure is reproduced in this document. This document is scoped to detection and remediation.

## 4. Detection & Audit Procedure

These checks require direct access to each Domain Controller (local admin or equivalent). Each check below includes the exact command, what a healthy result looks like, and what a vulnerable result looks like.

### 4.1 Registry check — single DC, interactive

Run directly on a Domain Controller (PowerShell, run as Administrator):

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
  -Name "VulnerableChannelAllowList" -ErrorAction SilentlyContinue
```

Interpreting the output:

- Command returns nothing / "property does not exist" → no exception configured. Healthy state.
- `VulnerableChannelAllowList : *` → **CRITICAL**. Every account is exempt from Zerologon protection on this DC.
- `VulnerableChannelAllowList : DESKTOP-OLD01$,PRINTSRV$` → specific machine accounts are exempt. Not automatically critical, but every listed name must be justified (see Section 5).

### 4.2 Registry check — all Domain Controllers at once

Rather than logging into each DC manually, run this from a domain-joined admin workstation to pull the value from every DC in one pass:

```powershell
$DCs = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $DCs) {
    $val = Invoke-Command -ComputerName $dc -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
            -Name "VulnerableChannelAllowList" -ErrorAction SilentlyContinue
    }
    [PSCustomObject]@{ DC = $dc; AllowList = $val.VulnerableChannelAllowList }
}
```

This requires WinRM/PowerShell remoting enabled to the DCs and an account with rights to query the registry remotely (Domain Admin or a delegated equivalent). If remoting is not available, fall back to the manual per-DC check in 4.1.

### 4.3 Group Policy check

The registry value above is frequently set directly by a GPO, so the GPO itself must also be checked — clearing the registry without checking the GPO means it can silently reapply on the next policy refresh (typically every 90 minutes).

- Open Group Policy Management Console (GPMC) from a domain admin workstation.
- Locate the setting: `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > "Domain Controller: Allow vulnerable Netlogon secure channel connections"`.
- Check every GPO linked to the Domain Controllers OU — not just Default Domain Controllers Policy, since a custom GPO may have been created during the original 2020–2021 rollout.

To find this quickly without opening every GPO by hand:

```powershell
Get-GPO -All | ForEach-Object {
    $report = Get-GPOReport -Guid $_.Id -ReportType Xml
    if ($report -match "VulnerableChannelAllowList") {
        Write-Output "Match found in GPO: $($_.DisplayName)"
    }
}
```

### 4.4 Event log correlation

Before removing any entry, confirm whether it is still actively being used — removing an exception a legacy device still depends on will break that device's authentication immediately.

```powershell
Get-WinEvent -LogName System -ComputerName <DCName> |
    Where-Object { $_.ProviderName -eq "Netlogon" } |
    Select-Object TimeCreated, Id, Message -First 50
```

Look specifically for Event ID 5827 / 5828 (Netlogon denied a vulnerable connection) and 5829/5830 (Netlogon allowed a vulnerable connection because the account is on the allow-list). A recent 5829/5830 for an account confirms it is actively relying on the exception right now.

## 5. Remediation

Do not simply delete the registry value or disable the GPO immediately — confirm first, then remediate, then re-verify. Skipping the confirmation step can cause an outage for a device that is still legitimately using the exception.

- **Step 1 — Inventory:** for every entry found in Section 4, record the account name, which DC(s) it appeared on, and whether Section 4.4 shows recent activity for it.
- **Step 2 — Owner confirmation:** identify who owns the device behind each account and confirm whether it still needs the exception.
- **Step 3a — If no longer needed:** remove just that account from the list rather than clearing the whole value.

```powershell
$current = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").VulnerableChannelAllowList
$updated = ($current -split "," | Where-Object { $_ -ne "DESKTOP-OLD01$" }) -join ","

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -Name "VulnerableChannelAllowList" -Value $updated
```

- **Step 3b — If the value is `*` or the list is empty after cleanup:** remove the property entirely and disable/un-link the associated GPO.

```powershell
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -Name "VulnerableChannelAllowList" -ErrorAction SilentlyContinue
```

- **Step 3c — If a legacy device genuinely still needs the exception:** keep only that specific account name (never a wildcard), document the business reason formally, get security sign-off, and set a reminder to revisit it (e.g. 90 days) rather than leaving it indefinitely.
- **Step 4 — Re-verify:** re-run the checks in Section 4 on every DC to confirm the value matches what was intended, and confirm via `gpresult` or a forced `gpupdate` that policy didn't silently reapply the old value.
- **Step 5 — Going forward:** consider alerting on future changes to this registry value / GPO (e.g. via a scheduled task or SIEM rule) so a new exception is caught immediately instead of being found again in a future audit.

## 6. References

- CVE-2020-1472 — Netlogon Elevation of Privilege Vulnerability (Zerologon)
- Microsoft: `VulnerableChannelAllowList` / Netlogon secure channel enforcement guidance
- Neff, Holl, Borgolte — ["Onelogon: Taking over Active Directory Accounts via Netlogon"](https://github.com/rub-softsec/onelogon), USENIX WOOT 2026 (Ruhr University Bochum)
