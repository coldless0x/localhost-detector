# LocalhostDetector

A lightweight Windows console utility that enumerates active TCP connections involving `127.0.0.1` and maps each connection to its owning process.

Useful for security research, malware analysis, and incident response when you need to identify which processes are communicating over localhost — including listeners, established sessions, and transient states.

---

## Features

- **Process-aware output** — Resolves PID to executable name via the Windows process snapshot API.
- **Full localhost coverage** — Reports connections where either the local or remote endpoint is `127.0.0.1`.
- **TCP state visibility** — Displays connection state (`LISTEN`, `ESTABLISHED`, `CLOSE_WAIT`, `TIME_WAIT`, `SYN_SENT`, and others).
- **Grouped by process** — Connections are organized per PID for quick triage.
- **Fast scan** — Single-pass enumeration with elapsed time reported at the end.
- **No static imports** — Core Win32 and networking APIs are resolved at runtime.

---

## Use Cases

| Scenario | What LocalhostDetector helps with |
|----------|-----------------------------------|
| Malware triage | Spot suspicious localhost tunnels, proxies, or C2 relay processes |
| Development & debugging | See which app owns a port on `127.0.0.1` |
| Forensics | Correlate loopback traffic with running processes |
| Hiding detection | Complement process-enumeration tools (e.g. DKOM checks) with network-level visibility |

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10 or later (x64 recommended) |
| **Toolchain** | Visual Studio 2022 with the **v143** platform toolset and Windows 10 SDK |
| **Privileges** | Standard user is sufficient for most connections; run as Administrator if you need broader process name resolution in protected contexts |

---

## Building

### Option A — Visual Studio

1. Clone the repository.
2. Open `LocalhostDetector.vcxproj` in Visual Studio 2022.
3. Select **Release \| x64** (recommended).
4. Build the project (**Ctrl+Shift+B**).

The executable is produced at:

```
x64\Release\LocalhostDetector.exe
```

### Option B — MSBuild (command line)

```powershell
msbuild LocalhostDetector.vcxproj /p:Configuration=Release /p:Platform=x64
```

---

## Usage

Run the executable from a console window:

```powershell
.\LocalhostDetector.exe
```

The tool performs a single scan, prints results, and waits for a key press before exiting.

No command-line arguments are required.

---

## Example Output

```
[+] LOCALHOST SCANNER
[+] TCP localhost connections by process

[+] Scanning TCP connections...

[+] Processes with localhost connections:

[+] PID    1234  chrome.exe  (2 connections)
[+]     ESTABLISHED  127.0.0.1:54321 -> 127.0.0.1:8080
[+]     LISTEN       127.0.0.1:8080  (listening)

[+] PID    5678  node.exe  (1 connections)
[+]     ESTABLISHED  127.0.0.1:3000 -> 127.0.0.1:54321

[+] Scan done in 42 ms

[+] Press any key to exit...
```

If no localhost connections are found:

```
[+] No localhost connections found.
```

---

## How It Works

1. **Process map** — `CreateToolhelp32Snapshot` walks the process list and builds a PID → executable name table.
2. **TCP table** — `GetExtendedTcpTable` (`iphlpapi.dll`) retrieves all TCP connections with owning PID (`TCP_TABLE_OWNER_PID_ALL`).
3. **Filter** — Entries where `dwLocalAddr` or `dwRemoteAddr` equals `0x0100007F` (`127.0.0.1`) are kept.
4. **Report** — Results are grouped by PID, with local/remote endpoints and TCP state printed for each connection.

---

## Project Structure

```
LocalhostDetector/
├── main.cpp                    # Application entry point and scan logic
├── LocalhostDetector.vcxproj   # Visual Studio project file
└── README.md
```

This tool is part of the broader **Unhide tool** family, focused on detecting hidden or anomalous process behavior on Windows.

---

## Limitations

- **TCP only** — UDP and other protocols are not scanned.
- **IPv4 localhost** — Only `127.0.0.1` is matched; `::1` (IPv6 loopback) is not included.
- **Point-in-time** — Output reflects the state at scan time; short-lived connections may be missed.
- **Process names** — Resolved from the snapshot; renamed or terminated processes may appear as `?`.

---

## Disclaimer

This software is provided for **educational and authorized security research** purposes only.

You are responsible for ensuring you have permission to analyze systems you run this tool against. The authors assume no liability for misuse.

---

## License

Specify a license before publishing (e.g. MIT, Apache 2.0). If none is declared, all rights are reserved by default under copyright law.

---

## Contributing

Issues and pull requests are welcome. Please keep changes focused and match the existing code style.
