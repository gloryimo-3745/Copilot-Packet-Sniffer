# Risk memo

## Scope

This tool is intended for supervised learning on a single local interface on
the operator's own computer. It is not intended for monitoring third-party
devices, bypassing access controls, or collecting packet contents.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Capturing traffic without valid permission | Require the exact authorization phrase before interface selection and make the capture API refuse to run unless authorization is explicitly passed. The operator must still determine whether they have permission. |
| Capturing more traffic than needed | Bind the capture to one user-selected local interface, disable promiscuous mode, apply a TCP/UDP IPv4/IPv6 BPF filter, and stop after 25 matching packets. |
| Sensitive addresses appearing in output | Replace IP and MAC addresses with `[REDACTED]` during metadata extraction, before records can be printed or written. |
| Payload or packet capture retention | Do not access raw payload fields, store captured Scapy packets, or write pcap/pcapng files. Persist only JSON metadata. |
| DNS metadata reveals user activity | Replace every DNS question name with `[REDACTED]` because browsing-related DNS metadata may be sensitive. Retain only question type and basic response metadata, not DNS answer resource data. |
| User mistakes metadata for anonymized data | Explain that DNS question names and IP/MAC addresses are redacted, but timestamps, ports, DNS question types, and traffic patterns remain. Do not treat the output as fully anonymous. |
| Capture setup differs by platform | Document that Windows generally needs Npcap and may require elevated privileges. Capture errors are not suppressed by the program. |

## Review notes

`count=25` limits the capture to 25 packets accepted by the BPF filter; if
traffic is idle, Scapy waits for matching packets. `store=False` avoids keeping
the packet list in Scapy's result object, while the callback retains only
sanitized dictionaries. The program does not make authorization decisions on
the user's behalf; consent and legal scope must be confirmed before use.
