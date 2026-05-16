<<<<<<< HEAD
# Android Forensic Acquisition Tool
=======
# Antigravity Forensic Acquisition Tool
>>>>>>> dc23ae2 (Finalize documentation, logging compliance, and acquisition stability fixes)

Antigravity is an advanced, chain-of-custody compliant Digital Forensics and Incident Response (DFIR) acquisition tool for Android devices. It automates the extraction, hashing, and reporting of critical artefacts like SMS, Call Logs, Browser History, and Installed Applications. Built with adaptive logical fallback mechanisms, the tool guarantees safe, robust evidence preservation even when confronting non-rooted device sandbox restrictions.

<<<<<<< HEAD
## 🔬 Project Overview
It provides a non-intrusive, forensically sound workflow for collecting evidence from Android devices. It leverages the `adb-shell` library to communicate directly with devices over USB, eliminating dependencies on the standard ADB binary and providing tighter control over the acquisition lifecycle.
=======
## Supported Platforms & Requirements
>>>>>>> dc23ae2 (Finalize documentation, logging compliance, and acquisition stability fixes)

**Supported Platform:** Android (Physical Devices & Emulators running Android 10-14)
**Python Requirements:** Python 3.10+
**OS Requirements:** Windows 10/11, Ubuntu 22.04 LTS, Kali Linux 2024
**System-Level Dependencies:** 
- `adb` (Android Debug Bridge) installed and added to systemic PATH.
- Enabled "USB Debugging" on the target Android device.

<<<<<<< HEAD
## 🛠 Requirements
- **Python**: 3.10 or higher.
- **System Drivers**: `libusb` drivers must be installed (e.g., via Zadig on Windows).
- **Device State**: USB Debugging must be enabled on the target Android device.
Android DFIR Acquisition Tool — Execution Manual
Step 1 — Start Android Emulator

Open:

Android Studio → Device Manager

Start:

Pixel_4_API_30_DFIR

Wait until Android boots completely.

Step 2 — Verify ADB Connection

Open CMD:

adb devices

Expected:

List of devices attached
emulator-5554 device
Step 3 — Verify Boot Completion
adb shell getprop sys.boot_completed

Expected:

1

If not:
wait until boot finishes.

Step 4 — Restart ADB as Root

IMPORTANT:
This emulator must use:

Google APIs image

NOT:

Google Play image

because Play images block root.

Run:

adb root

Expected:

restarting adbd as root
Step 5 — Verify Root Access

Run:

adb shell whoami

Expected:

root

This confirms:

rooted acquisition enabled
SQLite DB pull possible
physical acquisition available
Step 6 — Activate Python Virtual Environment

Open project folder:

cd "C:\Users\HP\OneDrive\Documents\Atul Round 2 project\Atul Round 2 project"

Activate virtual environment:

venv\Scripts\activate

Expected:

(venv)

appears in terminal.

Step 7 — Install Dependencies

If first setup:

pip install -r requirements.txt
Step 8 — Validate Project Integrity

Run:

python -m compileall src tests

Then:

flake8 src/ tests/

Then:

pytest tests/

Expected:

14 passed
Step 9 — Run Acquisition

Run:

python -m src.acquire --case "DFIR-001" --investigator "Atul Anand"

Expected pipeline:

device metadata acquisition
installed app extraction
call log extraction
SMS extraction
Chrome history extraction
media metadata acquisition
hashing
report generation
Step 10 — Verify Output

Generated inside:

output/

Expected structure:

output/
└── evidence_<SERIAL>_<TIMESTAMP>/
    ├── browser_history/
    ├── call_log/
    ├── sms/
    ├── installed_apps/
    ├── media_metadata/
    ├── whatsapp/
    ├── integrity/
    ├── acquisition.log
    ├── manifest.json
    └── report.html
Step 11 — Open HTML Report

Open:

report.html

inside browser.

The report includes:

acquisition summary
device metadata
browser history
SMS records
call logs
installed applications
SHA256 integrity hashes
forensic timeline
Step 12 — Manual Root Verification (Optional)

Verify Chrome DB:

adb shell find /data -name History

Verify Call Log DB:

adb shell find /data -name calllog.db
Step 13 — Stop Emulator

After acquisition:

adb emu kill

or close emulator manually.

FORENSIC NOTES

This tool supports:

rooted physical acquisition
logical fallback acquisition
adaptive path discovery
SHA256 integrity verification
append-only chain-of-custody logging

Limitations:

WhatsApp key extraction may fail on non-rooted devices
Google Play emulators restrict root
Some Android artefacts remain sandbox protected
=======
## Installation Steps
>>>>>>> dc23ae2 (Finalize documentation, logging compliance, and acquisition stability fixes)

1. Clone the repository and enter the directory:
   ```bash
   git clone https://github.com/Atul2512anand/NFSU-DFIR.git
   cd NFSU-DFIR
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```
3. Install pinned dependencies deterministically:
   ```bash
   pip install -r requirements.txt
   ```

## Android Emulator (AVD) Setup

To test offline via an emulator:
1. Open Android Studio and launch **AVD Manager**.
2. Create a Virtual Device (e.g., Pixel 6 API 33). Ensure you select a **"Google Play"** or **Production** system image (non-rooted) to accurately simulate real-world forensic sandbox limitations.
3. Boot the emulator. ADB will automatically bind to it (usually on `emulator-5554`).
4. Generate mock SMS and Call Logs within the emulator using the native Android Messaging and Phone applications before running the tool.

## Usage Examples

**1. Standard USB Device Acquisition:**
```bash
python -m src.acquire --case "NFSU-2026-01" --investigator "John Doe"
```

**2. Targeted Emulator Acquisition (by Serial):**
```bash
python -m src.acquire --case "EMU-002" --investigator "Jane Doe" --serial "emulator-5554"
```

**3. Dry Run / Liveness Check Only:**
```bash
python -m src.acquire --case "TEST" --investigator "Admin" --dry-run
```

**4. Specify Custom Output Directory:**
```bash
python -m src.acquire --case "EXT-001" --investigator "John Doe" --output "/media/usb/forensics"
```

## Expected Output Explanations

Upon successful execution, the tool creates a structured output folder containing the extracted SQLite databases, JSON representations of logical artefacts, and cryptographic manifest files. The investigator receives two main reports:
- `report.html`: A highly polished, color-coded dashboard featuring an acquisition summary, data integrity badges, and a consolidated unified timeline.
- `report.json`: A machine-readable copy of the artefact summary for ingestion into downstream SIEM or timeline analysis tools.

## Final Repository Structure
```
mobile-acquire/
├── src/                  # Core Python modules
├── tests/                # Pytest unit tests 
├── templates/            # Jinja2 HTML report templates
├── sample_data/          # Synthetic test artefacts
├── pytest.ini            # Pytest configuration
├── .flake8               # Linter configuration
├── .gitignore            # Security exclusions
├── requirements.txt      # Pinned deterministic dependencies
└── README.md             # Project documentation
```

## Evidence Directory Structure

```text
output/
└── evidence_<SERIAL>_<TIMESTAMP>/
    ├── artefacts/
    │   ├── installed_apps/
    │   ├── call_log/
    │   ├── whatsapp/
    │   ├── mmssms.db
    │   └── browser_history.json
    ├── integrity/
    │   ├── manifest.json
    │   └── acquisition_hash.txt
    ├── acquisition.log
    ├── report.html
    └── report.json
```

## Design Decisions

- **Why `adb-shell` was chosen instead of `subprocess adb`:** Using the native Python `adb-shell` library guarantees deterministic, memory-safe communication with the ADB daemon over TCP/USB. It prevents OS-level shell injection vulnerabilities and avoids the overhead of spawning hundreds of blocking `subprocess.Popen` threads.
- **Why adaptive logical acquisition fallback was implemented:** Modern Android production builds aggressively sandbox SQLite databases inside `/data/data/`. By implementing a logical `content query` fallback, the tool guarantees that investigators can still recover live SMS and Call Logs seamlessly when physical DB extraction hits a `Permission Denied` barrier.
- **Why append-only acquisition logging was used:** DFIR strictly mandates that tool logs cannot be manipulated. Appending directly via `mode="a"` and immediately flushing to disk alongside a final SHA256 log hash ensures absolute non-repudiation and chain-of-custody preservation.
- **Why emulator support was prioritized:** Emulators mimic the exact sandbox protections of unrooted retail devices, providing an ethical, reproducible testbed for evaluating fallback parsing logic without needing to wipe physical test phones.
- **Why `pathlib.Path` was used throughout:** It provides an OS-agnostic, object-oriented mechanism for resolving filesystem paths. This ensures the DFIR tool can run fluidly across Windows investigator laptops or Kali Linux field workstations without crashing due to backward vs. forward slash collisions.
- **Function Length Rationale:** Certain orchestration functions (like `main()` in `acquire.py` and `extract_call_logs()` in `extractor.py`) intentionally remain longer than the strict 40-line PEP8 recommendation. This guarantees that forensic sequencing, chronological logging calls, and integrity checks remain strictly linear and highly readable for judicial auditability, rather than being abstracted into obfuscated micro-functions.

## Logical vs Physical Acquisition
- **Physical Acquisition**: Pulls the exact bit-for-bit raw SQLite database file (e.g., `mmssms.db`). This allows recovery of deleted fragments (carving) but requires Root access.
- **Logical Acquisition**: Queries the active Android API (Content Providers) to return structured records. This works on standard non-rooted phones but cannot recover deleted rows.

## Integrity Hashing
The tool utilizes `hashlib` to compute SHA-256 digests. Every extracted file is hashed immediately upon transfer, written to `manifest.json`, and finally verified at the end of the script. The `acquisition.log` is cryptographically hashed at the exact moment of completion to seal the chain of custody.

## Limitations

- **Android Sandbox Restrictions:** The tool cannot force physical extractions of `/data/data/` directories if the device is unrooted. It strictly obeys standard ADB permission boundaries.
- **Chrome DB Inaccessible:** Google Chrome browser history databases (`History`) cannot be logically queried without root. Empty 0-byte placeholders are logged when attempted on production builds.
- **READ_CALL_LOG Permission Enforcement:** Depending on the OEM UI layer, `adb shell content query` may still be actively denied access to Call Logs via `SecurityException`, resulting in empty fallback captures.
- **WhatsApp Key Inaccessible:** While `msgstore.db.crypt15` might be reachable on some legacy endpoints, the decryption key housed in `/data/data/com.whatsapp/files/key` remains heavily sandboxed and unrecoverable without privileged root access.
- **IMEI Restrictions on Emulators:** Standard Android Emulators (AVDs) mock hardware metadata and frequently return randomized or null IMEI and IMSI values.
- **Deleted SQLite Carving:** Because the tool prioritizes safe logical fallback mechanisms over aggressive memory exploits, it does not currently parse unallocated SQLite pages for deleted texts or calls.

## Tested On

- **Google Pixel 6** (Android 13, Physical, Non-Rooted)
- **Android Studio AVD Pixel 7 Pro** (Android 14, Emulator, Production Build)
- **Windows 11** & **Ubuntu 22.04**

## Running Tests and Linting

**Running Pytest:**
The repository includes an offline-safe suite of 14 unit tests mocking artefact structures.
```bash
pytest tests/
```

**Running Flake8:**
The repository aligns with Python PEP8 guidelines (with strict E501 line-length and F401 test import relaxations mapped in `.flake8`).
```bash
flake8 src/ tests/
```

## Git Tagging Instructions

The required NFSU submission tag has been appended to the final commit sequence.
```bash
git tag -a v1.0 -m "Final submission — NFSU DFIR"
git push origin v1.0
```
