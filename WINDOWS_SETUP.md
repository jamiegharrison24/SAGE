# Windows Setup Guide for SAGE

This guide walks you through setting up SAGE on a Windows 11 machine from scratch.

---

## Prerequisites

Before running the setup script you need the following installed. If you already have one, skip its section.

### 1. Python 3 (3.9 or later)

1. Open the Microsoft Store and search for **Python 3.12**, or download from https://www.python.org/downloads/
2. During installation, tick **"Add python.exe to PATH"** — this is essential.
3. Verify in a new terminal:
   ```
   python --version
   pip --version
   ```

### 2. Git

1. Download the installer from https://git-scm.com/download/win
2. Run it with default options.
3. Verify:
   ```
   git --version
   ```

### 3. Windows Subsystem for Linux (WSL) with Ubuntu

SAGE uses **FlexFringe**, a C++ binary that must be compiled from source. On Windows this is done inside WSL. You only need to do this once.

**Check if WSL is already installed:**
```powershell
wsl --list --verbose
```

If you see `Ubuntu` listed, you're done. Otherwise:

1. Open **PowerShell as Administrator** (right-click the Start button → *Terminal (Admin)*).
2. Run:
   ```powershell
   wsl --install -d Ubuntu
   ```
3. Reboot when prompted.
4. After reboot, Ubuntu will open and ask you to create a UNIX username and password. Choose anything — it is only used inside WSL.
5. After Ubuntu finishes setting up, close the window.

> **Corporate/managed machines:** If `wsl --install` fails, WSL may need to be enabled via Group Policy or the Windows Features dialog (`OptionalFeatures.exe` → *Windows Subsystem for Linux*). Contact your IT department if blocked.

### 4. winget (Windows Package Manager)

`winget` is built into Windows 11 and used to install Graphviz. Confirm it works:
```
winget --version
```
If the command is not found, install the **App Installer** package from the Microsoft Store.

---

## Getting the Code

Clone the SAGE repository into a directory of your choice:
```powershell
git clone https://github.com/tudelft-cda-lab/SAGE.git
cd SAGE
```

---

## Automated Setup

This ships with a PowerShell setup script that handles everything else automatically:

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1
```

The script performs these steps (in order):

| Step | What it does |
|------|-------------|
| **Graphviz** | Installs Graphviz via `winget` and adds it to your user PATH |
| **Python packages** | Runs `pip install -r requirements.txt` (`graphviz`, `requests`, `numpy`, `matplotlib`) |
| **FlexFringe** | Clones FlexFringe, compiles it inside WSL/Ubuntu, and copies the binary to `FlexFringe/flexfringe` |
| **Config** | Copies `spdfa-config.ini` to `FlexFringe/ini/spdfa-config.ini` |
| **Alert data** | Decompresses all `.gz` alert files in the `alerts/` directory |

The FlexFringe compilation step downloads build tools (`cmake`, `g++`, `libboost-all-dev`) into your WSL Ubuntu environment and compiles the binary. **This takes 5–15 minutes** depending on your machine. Subsequent runs skip the build if the binary already exists.

### What to expect

```
=== Installing Graphviz ===
=== Installing Python packages ===
=== Building FlexFringe via WSL ===
Installing build tools and compiling FlexFringe (this takes several minutes)...
FlexFringe built successfully.
=== Setting up FlexFringe config ===
=== Decompressing alert files ===
  Decompressed: NationalTeam1.json__.gz
  ...
=== Setup complete ===
```

### PATH note

After Graphviz is installed the script adds it to your **user** PATH. Open a **new** terminal window before running SAGE so the updated PATH is loaded.

---

## Manual Setup (if the script fails)

Follow these steps if you prefer not to use the script, or if a step fails. (If the script fails, probably just talk to to Jamie or Toby and get them to fix it)

### 1. Install Graphviz

```powershell
winget install graphviz.graphviz --silent
```

Then add `C:\Program Files\Graphviz\bin` to your user PATH:
1. Search for *"Edit the system environment variables"* in the Start menu.
2. Click **Environment Variables**.
3. Under *User variables*, select **Path** → **Edit** → **New**.
4. Paste `C:\Program Files\Graphviz\bin` and click OK.

Verify in a new terminal:
```
dot -V
```

### 2. Install Python packages

```powershell
pip install graphviz requests numpy matplotlib
```

### 3. Build FlexFringe

Open a WSL Ubuntu shell (`wsl -d Ubuntu`) and run:

```bash
sudo apt-get install -y cmake g++ libboost-all-dev git

TMP=$(mktemp -d)
git clone https://github.com/tudelft-cda-lab/FlexFringe "$TMP"
cmake -S "$TMP" -B "$TMP/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$TMP/build" --parallel $(nproc)
```

Copy the compiled binary back to your Windows project directory. Replace `<drive>` and `<path>` with the actual path to your SAGE clone — for example, a clone at `C:\Projects\SAGE` becomes `/mnt/c/Projects/SAGE`:

```bash
cp "$TMP/build/flexfringe" /mnt/<drive>/<path>/FlexFringe/flexfringe
```

### 4. Set up FlexFringe config

In PowerShell (from the SAGE directory):
```powershell
New-Item -ItemType Directory -Force FlexFringe\ini
Copy-Item spdfa-config.ini FlexFringe\ini\spdfa-config.ini
```

### 5. Decompress alert files

In PowerShell (from the SAGE directory):
```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
Get-ChildItem alerts -Recurse -Filter "*.gz" | ForEach-Object {
    $out = $_.FullName -replace '\.gz$', ''
    if (-not (Test-Path $out)) {
        $in = [System.IO.File]::OpenRead($_.FullName)
        $gz = [System.IO.Compression.GZipStream]::new($in, [System.IO.Compression.CompressionMode]::Decompress)
        $o  = [System.IO.File]::Create($out)
        $gz.CopyTo($o)
        $o.Close(); $gz.Close(); $in.Close()
    }
}
```

---

## Verifying the Installation

Check that the key pieces are in place:

```powershell
# Python packages
python -c "import graphviz, requests, numpy, matplotlib; print('Python packages OK')"

# Graphviz renderer
dot -V

# FlexFringe binary
Test-Path FlexFringe\flexfringe   # should print True

# Config file
Test-Path FlexFringe\ini\spdfa-config.ini   # should print True

# Alert files decompressed (example)
Test-Path alerts\cptc-2017\NationalTeam1.json   # should print True
```

---

## Running SAGE

All commands are run from the SAGE project directory in PowerShell or Command Prompt.

**CPTC 2017 dataset:**
```powershell
python sage.py alerts/cptc-2017/ exp-2017 --dataset cptc
```

**CPTC 2018 dataset** (custom time window and episode width):
```powershell
python sage.py alerts/cptc-2018/ exp-2018 -t 2.0 -w 200 --dataset cptc
```

**CCDC dataset** (keep intermediate files):
```powershell
python sage.py alerts/ccdc/ exp-ccdc --dataset other --keep-files
```

Output attack graphs (`.png` and `.svg`) are written to a directory named `<experiment_name>AGs/` (e.g. `exp-2017AGs/`).

### Key command-line options

| Option | Default | Description |
|--------|---------|-------------|
| `-t THRESHOLD` | `1.0` | Time threshold (seconds) for deduplicating alerts |
| `-w WINDOW` | `150` | Sliding window size (seconds) for episode aggregation |
| `--dataset` | required | Alert format: `cptc` or `other` |
| `--keep-files` | off | Keep intermediate FlexFringe files after the run |

---

## Running Tests

```powershell
# Unit tests
python tests.py

# Style check
pycodestyle --ignore=E501,W503,W504 *.py
pycodestyle --ignore=E501,W503,W504 signatures/*.py
```

---

## Troubleshooting

### `wsl: command not found` or WSL fails to start
Enable WSL in Windows Features: press `Win+R`, type `OptionalFeatures.exe`, and tick *Windows Subsystem for Linux*. Reboot, then re-run `wsl --install -d Ubuntu`.

### `dot: command not found` when running SAGE
Open a new terminal after installation. If still missing, confirm `C:\Program Files\Graphviz\bin` is in your PATH (see Step 1 of Manual Setup).

### `pip` is not recognised
Python was installed without being added to PATH. Either reinstall Python with the *"Add to PATH"* option ticked, or use `py -m pip` instead of `pip`.

### FlexFringe build fails: `cmake: command not found`
Inside your WSL Ubuntu shell run:
```bash
sudo apt-get update && sudo apt-get install -y cmake g++ libboost-all-dev git
```
Then re-run the build step.

### FlexFringe build fails: `boost` errors
Ensure `libboost-all-dev` installed successfully. On some Ubuntu versions you may need:
```bash
sudo apt-get install -y libboost-program-options-dev libboost-filesystem-dev
```

### `FlexFringe/flexfringe` not found at runtime
The binary must be at exactly `FlexFringe/flexfringe` relative to the SAGE project directory (no `.exe` extension — it is a Linux binary run via WSL). Confirm with:
```powershell
Test-Path FlexFringe\flexfringe
```

### Internet access errors during the run
SAGE downloads the IANA port mapping at startup from `https://www.iana.org/...`. Ensure outbound HTTPS is allowed. Behind a corporate proxy, set:
```powershell
$env:HTTPS_PROXY = "http://your-proxy:port"
python sage.py ...
```