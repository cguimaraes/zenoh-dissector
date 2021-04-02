# Zenoh Dissector Test Suite
Wireshark dissectors developed in Lua are tighly coupled with the
[Wireshark Lua API](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html).
This makes the development of automated tests a complex task,
requiring changes in the structure of the code to isolate non-dependent code
on Wireshark Lua API.

[WireBait](https://github.com/MarkoPaul0/WireBait) tries to fill this gap,
but its development is no longer supported. As such, this option was dropped
since updates on the Wireshark Lua API might make break the whole test suite.

As a better alternative in the mid- and long-term, the test suite is developed
in Python, using pyshark and anonymized packet traces.

## Dependencies
 - **unittest**: Python unit testing framework
 - **pyshark**: Python wrapper for tshark
 - (optional) **pktanon**: Packet trace anonymization

## Usage
To run all tests by executing the following command:

```bash
  python3 tests-across-pcaps.py
```

## Anonymize traces
You can anonymize traces using a variety of tools.
Pktanon is one of those tools, which can perform network trace anonymization
by executing following command:

```bash
  pktanon -c ./traces/profile.xml trace.pcap trace-anonymized.pcap
```
