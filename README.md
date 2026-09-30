# Ethical Educational Packet Sniffer

This small Scapy program demonstrates basic packet metadata inspection on one
network interface belonging to the computer running it. It is not a general
network-monitoring or packet-forensics tool.

## AI Use Policy

This educational example was prepared with AI assistance. Read and understand
the code, review its behavior, and follow your institution's or organization's
AI-use and software-review policies before using or adapting it. Do not submit
confidential information, credentials, or captured traffic to an AI service.
You are responsible for validating the code and complying with applicable
policies and laws.

## Authorized-use limits

- Run it only on your own computer and only when you are authorized to inspect
  the traffic visible on the selected local interface. Owning the computer does
  not by itself authorize monitoring other people's communications or networks.
- The program requires the exact authorization phrase before listing interfaces
  or starting capture. Declining exits without capturing or writing output.
- It captures on one selected interface with promiscuous mode disabled and a
  fixed BPF filter for IPv4/IPv6 TCP or UDP traffic.
- It stops after 25 matching packets. It may wait until 25 packets arrive.
- It displays and saves metadata only. IP and MAC addresses are replaced with
  `[REDACTED]` before either output; raw payloads are never inspected, displayed,
  or saved. DNS question names are also replaced with `[REDACTED]` because
  browsing-related DNS metadata may be sensitive. DNS question type and basic
  response metadata remain in the output; protect and delete the sanitized
  output when it is no longer needed.
- No raw packet capture file is created. `output/sanitized_packets.json` is the
  default metadata output; the `output/` folder is created when the program
  runs.

## Requirements and run

Python 3.10+ and Scapy are required. On Windows, packet capture generally
requires Npcap; an elevated terminal may be required by the capture driver.

```powershell
python -m pip install -r requirements.txt
python sniffer.py
```

Type the complete authorization phrase printed by the program, then enter the
name of one of the listed local interfaces. Capture is limited to exactly 25
matching packets. Do not choose an interface or run the program unless the
capture is authorized.

## How the code works

1. `main()` requests an explicit authorization phrase before doing anything
   that starts capture. It then lists local interfaces and validates the
   selected interface against that list.
2. `capture_metadata()` refuses to start unless authorization was confirmed.
   Its Scapy `sniff()` call applies the fixed BPF filter, requests a count of
   25, uses `prn=on_packet` for each packet, disables packet storage with
   `store=False`, and sets `promisc=False`.
3. `extract_metadata()` reads only decoded header fields: IPv4/IPv6, TCP/UDP
   ports and TCP flags, and DNS response metadata. If a DNS question exists,
   its name is always `[REDACTED]`; only its type is retained. DNS names can
   reveal browsing-related activity. The function never reads a packet's raw
   payload. IP and MAC values are replaced with `[REDACTED]` while constructing
   the record.
4. The callback prints only the sanitized record. After capture, only those
   records are written as JSON. The output extension is checked to prevent
   writing to a packet-capture file.

## Tests

The tests use Python's built-in `unittest` library and a mocked Scapy capture;
they do not start a live packet capture:

```powershell
python -m unittest discover -s tests -v
```
