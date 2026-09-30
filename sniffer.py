"""Capture a small, consent-gated sample of local interface traffic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scapy.all import DNS, DNSQR, Ether, IP, IPv6, TCP, UDP, get_if_list, sniff

PACKET_LIMIT = 25
BPF_FILTER = "(ip and (tcp or udp)) or (ip6 and (tcp or udp))"
CONSENT_PHRASE = "I AM AUTHORIZED TO CAPTURE TRAFFIC ON THIS COMPUTER"
DEFAULT_OUTPUT = Path("output") / "sanitized_packets.json"
REDACTED = "[REDACTED]"


def extract_metadata(packet: Any, packet_number: int) -> dict[str, Any]:
    """Return a metadata-only record; never inspect or retain raw payload data."""
    record: dict[str, Any] = {
        "packet_number": packet_number,
        "timestamp": float(packet.time),
        "source_mac": REDACTED if Ether in packet else None,
        "destination_mac": REDACTED if Ether in packet else None,
        "source_ip": None,
        "destination_ip": None,
        "ip_version": None,
        "transport": None,
        "source_port": None,
        "destination_port": None,
        "tcp_flags": None,
        "dns": None,
    }

    if IPv6 in packet:
        record["ip_version"] = 6
        record["source_ip"] = REDACTED
        record["destination_ip"] = REDACTED
    elif IP in packet:
        record["ip_version"] = 4
        record["source_ip"] = REDACTED
        record["destination_ip"] = REDACTED

    if TCP in packet:
        transport = packet[TCP]
        record["transport"] = "TCP"
        record["source_port"] = int(transport.sport)
        record["destination_port"] = int(transport.dport)
        record["tcp_flags"] = str(transport.flags)
    elif UDP in packet:
        transport = packet[UDP]
        record["transport"] = "UDP"
        record["source_port"] = int(transport.sport)
        record["destination_port"] = int(transport.dport)

    if DNS in packet:
        dns = packet[DNS]
        question = packet[DNSQR] if DNSQR in packet else None
        record["dns"] = {
            "is_response": bool(dns.qr),
            "response_code": int(dns.rcode),
            "question_name": REDACTED if question is not None else None,
            "question_type": int(question.qtype) if question is not None else None,
            "answer_count": int(dns.ancount),
        }

    return record


def capture_metadata(
    interface: str,
    *,
    authorized: bool,
    output_path: Path = DEFAULT_OUTPUT,
) -> list[dict[str, Any]]:
    """Capture at most 25 filtered packets and persist sanitized records only."""
    if not authorized:
        raise PermissionError("Capture requires explicit authorization.")
    if output_path.suffix.lower() != ".json":
        raise ValueError("Sanitized metadata output must use a .json file.")

    records: list[dict[str, Any]] = []

    def on_packet(packet: Any) -> None:
        if len(records) >= PACKET_LIMIT:
            return
        record = extract_metadata(packet, len(records) + 1)
        records.append(record)
        print(json.dumps(record, sort_keys=True))

    sniff(
        iface=interface,
        filter=BPF_FILTER,
        count=PACKET_LIMIT,
        prn=on_packet,
        store=False,
        promisc=False,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(records, output_file, indent=2, sort_keys=True)
        output_file.write("\n")
    return records


def main() -> int:
    print(
        "This captures only traffic visible on a selected interface on this "
        "computer. Use it only where you are authorized."
    )
    confirmation = input(
        f'Type "{CONSENT_PHRASE}" to continue: '
    )
    if confirmation != CONSENT_PHRASE:
        print("Authorization not confirmed; no capture was started.")
        return 1

    interfaces = get_if_list()
    if not interfaces:
        raise RuntimeError("Scapy did not find any network interfaces.")

    print("Available local interfaces:")
    for interface in interfaces:
        print(f"  {interface}")
    selected = input("Interface to capture on: ").strip()
    if selected not in interfaces:
        raise ValueError("Select an interface listed above.")

    records = capture_metadata(selected, authorized=True)
    print(f"Captured {len(records)} packet(s); sanitized metadata saved to {DEFAULT_OUTPUT}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
