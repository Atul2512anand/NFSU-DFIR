# Antigravity Android Forensic Acquisition Tool

A production-grade, CLI-based Digital Forensics and Incident Response (DFIR) tool designed for the logical acquisition and analysis of Android mobile devices.

## 🔬 Project Overview
Antigravity provides a non-intrusive, forensically sound workflow for collecting evidence from Android devices. It leverages the `adb-shell` library to communicate directly with devices over USB, eliminating dependencies on the standard ADB binary and providing tighter control over the acquisition lifecycle.

## 🚀 Key Features
- **Direct USB Communication**: Pure Python implementation using `libusb`, bypassing `subprocess` calls.
- **Automated Evidence Collection**: 
    - **Communications**: SMS messages and Call Logs extraction.
    - **Web Activity**: Chrome browser history and metadata recovery.
    - **Applications**: Full enumeration of installed packages and versions.
    - **Storage Mapping**: Recursive metadata listing of `/sdcard/` with on-device hashing.
- **Integrity Management**: 
    - Immediate SHA-256 hashing of all acquired files.
    - Recursive evidence manifest generation.
    - Automated post-extraction verification.
- **Forensic Reporting**:
    - Professional, responsive HTML reports for investigators.
    - Machine-readable JSON reports for automated ingestion.
- **Robust Logging**: Thread-safe UTC logging with ISO 8601 'Z' suffix compliance.

## 🛠 Requirements
- **Python**: 3.10 or higher.
- **System Drivers**: `libusb` drivers must be installed (e.g., via Zadig on Windows).
- **Device State**: USB Debugging must be enabled on the target Android device.

## 📦 Installation
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd "Atul Round 2 project"
   ```
2. Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

## 💻 Usage Examples
**Note:** Ensure no other ADB servers are running (`adb kill-server`) before starting the acquisition.

### **Perform Full Acquisition**
```powershell
python -m src.acquire --case "CASE-2026-001" --investigator "Analyst_Atul"
```

### **Target Specific Device**
```powershell
python -m src.acquire --case "CASE-002" --investigator "Atul" --serial "9889abc123"
```

### **Dry Run (Connection Test)**
```powershell
python -m src.acquire --case "TEST" --investigator "Atul" --dry-run
```

## 📂 Output Directory Structure
Every acquisition creates a unique, timestamped folder:
```text
evidence_<SERIAL>_<TIMESTAMP>/
├── acquisition.log        # Complete forensic audit trail
├── manifest.json           # SHA-256 hashes of all evidence
├── report.html             # Investigator-ready evidence summary
├── report.json             # Machine-readable report data
├── artefacts/              # Raw acquired evidence
│   ├── mmssms.db           # SMS Database
│   ├── contacts2.db        # Call Log Database
│   ├── Chrome_History      # Browser History Database
│   └── ...
└── integrity/
    └── acquisition_hash.txt # SHA-256 "seal" of the session log
```

## 🏗 Architecture
- **`src/acquire.py`**: Central orchestrator for the acquisition lifecycle.
- **`src/device.py`**: USB discovery, authentication, and metadata retrieval.
- **`src/extractor.py`**: Logic for logical data pulling and storage mapping.
- **`src/parser.py`**: Specialized SQLite parsers for Android databases.
- **`src/hasher.py`**: Cryptographic integrity and manifest management.
- **`src/reporter.py`**: Jinja2-based multi-format report generation.

## 🧪 Testing
The project includes a comprehensive test suite (13+ tests) covering all core modules. Tests are designed to run **offline** without a physical device.
```powershell
python -m pytest tests/
```

## ⚠️ Limitations
- **Root Access**: Access to certain databases (SMS/Calls/Chrome) requires the target device to be rooted or have a debugging-enabled system image.
- **Encrypted Storage**: The tool performs logical acquisition; it does not bypass full-disk encryption (FDE/FBE) without device authorization.

## 🖥 Tested Environment
- **OS**: Windows 11
- **Python**: 3.13.5
- **Library**: `adb-shell[usb]` v0.4.4
- **Target**: Android 16 (Xiaomi/HyperOS)
