import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scapy.all import DNS, DNSQR, Ether, IP, IPv6, Raw, TCP, UDP

import sniffer


class SnifferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.output_path = Path(self.temp_directory.name) / "sanitized.json"

    def test_capture_requires_authorization_before_sniff_or_output(self) -> None:
        with patch("sniffer.sniff") as sniff_mock:
            with self.assertRaises(PermissionError):
                sniffer.capture_metadata(
                    "local-interface",
                    authorized=False,
                    output_path=self.output_path,
                )

        sniff_mock.assert_not_called()
        self.assertFalse(self.output_path.exists())

    def test_main_rejects_nonexact_consent_before_interface_or_capture(self) -> None:
        with patch("builtins.input", return_value=sniffer.CONSENT_PHRASE.lower()), \
             patch("sniffer.get_if_list") as interfaces_mock, \
             patch("sniffer.sniff") as sniff_mock, \
             patch("sniffer.capture_metadata") as capture_mock:
            with redirect_stdout(StringIO()):
                result = sniffer.main()

        self.assertEqual(result, 1)
        interfaces_mock.assert_not_called()
        sniff_mock.assert_not_called()
        capture_mock.assert_not_called()

    def test_capture_uses_filter_callback_and_exact_packet_limit(self) -> None:
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=43210, dport=443, flags="S")
        )

        def fake_sniff(**kwargs: object) -> None:
            callback = kwargs["prn"]
            for _ in range(int(kwargs["count"])):
                callback(packet)

        displayed = StringIO()
        with patch("sniffer.sniff", side_effect=fake_sniff) as sniff_mock:
            with redirect_stdout(displayed):
                records = sniffer.capture_metadata(
                    "local-interface",
                    authorized=True,
                    output_path=self.output_path,
                )

        sniff_mock.assert_called_once()
        call = sniff_mock.call_args.kwargs
        self.assertEqual(call["iface"], "local-interface")
        self.assertEqual(call["filter"], sniffer.BPF_FILTER)
        self.assertEqual(call["count"], 25)
        self.assertEqual(call["prn"].__name__, "on_packet")
        self.assertFalse(call["store"])
        self.assertFalse(call["promisc"])
        self.assertEqual(len(records), 25)
        self.assertEqual([record["packet_number"] for record in records], list(range(1, 26)))
        self.assertEqual(records[0]["ip_version"], 4)
        self.assertEqual(records[0]["transport"], "TCP")
        self.assertEqual(records[0]["source_port"], 43210)
        self.assertEqual(records[0]["tcp_flags"], "S")
        self.assertEqual(records[0]["source_ip"], sniffer.REDACTED)
        self.assertEqual(records[0]["source_mac"], sniffer.REDACTED)
        self.assert_no_raw_addresses(displayed.getvalue())
        self.assert_no_raw_addresses(self.output_path.read_text(encoding="utf-8"))

    def test_extracts_ipv6_udp_and_redacts_dns_question_name(self) -> None:
        packet = (
            Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:04")
            / IPv6(src="2001:db8::10", dst="2001:db8::20")
            / UDP(sport=53000, dport=53)
            / DNS(
                id=17,
                qr=0,
                qd=DNSQR(qname="example.org", qtype="AAAA"),
                ancount=0,
            )
        )

        record = sniffer.extract_metadata(packet, 1)

        self.assertEqual(record["ip_version"], 6)
        self.assertEqual(record["transport"], "UDP")
        self.assertEqual(record["source_port"], 53000)
        self.assertEqual(record["destination_port"], 53)
        self.assertEqual(
            record["dns"],
            {
                "is_response": False,
                "response_code": 0,
                "question_name": sniffer.REDACTED,
                "question_type": 28,
                "answer_count": 0,
            },
        )
        serialized = json.dumps(record)
        self.assertNotIn("2001:db8::10", serialized)
        self.assertNotIn("2001:db8::20", serialized)
        self.assertNotIn("02:00:00:00:00:03", serialized)
        self.assertNotIn("02:00:00:00:00:04", serialized)

    def test_raw_payload_secret_never_appears_in_returned_printed_or_saved_data(self) -> None:
        secret = "TEST-SECRET-PAYLOAD"
        packet = (
            Ether(src="02:00:00:00:00:05", dst="02:00:00:00:00:06")
            / IP(src="192.0.2.30", dst="198.51.100.40")
            / UDP(sport=53001, dport=53)
            / DNS(qd=DNSQR(qname="private.example", qtype="A"), ancount=0)
            / Raw(load=secret.encode("ascii"))
        )

        def fake_sniff(**kwargs: object) -> None:
            kwargs["prn"](packet)

        displayed = StringIO()
        with patch("sniffer.sniff", side_effect=fake_sniff):
            with redirect_stdout(displayed):
                records = sniffer.capture_metadata(
                    "local-interface",
                    authorized=True,
                    output_path=self.output_path,
                )

        saved_json = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn(secret, json.dumps(records))
        self.assertNotIn(secret, displayed.getvalue())
        self.assertNotIn(secret, saved_json)
        self.assertEqual(records[0]["dns"]["question_name"], sniffer.REDACTED)

    def test_rejects_non_json_output(self) -> None:
        with patch("sniffer.sniff") as sniff_mock:
            with self.assertRaises(ValueError):
                sniffer.capture_metadata(
                    "local-interface",
                    authorized=True,
                    output_path=Path(self.temp_directory.name) / "capture.pcap",
                )
        sniff_mock.assert_not_called()

    def assert_no_raw_addresses(self, text: str) -> None:
        for address in (
            "192.0.2.10",
            "198.51.100.20",
            "02:00:00:00:00:01",
            "02:00:00:00:00:02",
        ):
            self.assertNotIn(address, text)


if __name__ == "__main__":
    unittest.main()
