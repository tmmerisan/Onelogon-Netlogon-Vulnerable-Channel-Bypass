# Onelogon-Netlogon-Vulnerable-Channel-Bypass
Onelogon — Netlogon Vulnerable Channel Bypass
Vulnerability Overview, Exploitation Path & Remediation Guidance

TypeDetection & Remediation GuideDate2026-07-04RelatedCVE-2020-1472 (Zerologon)


1. Summary

A publicly disclosed technique, referred to as "Onelogon", demonstrates a bypass of the Zerologon (CVE-2020-1472) remediation on Active Directory Domain Controllers. The bypass does not target a new flaw in the Netlogon Remote Protocol (MS-NRPC) itself — it targets legacy compatibility exceptions that administrators may have left enabled after the original Zerologon patch cycle (August 2020 – February 2021).
