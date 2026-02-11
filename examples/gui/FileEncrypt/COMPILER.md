# FileEncrypt - Build Instructions

## Description

GUI application for file encryption/decryption with threaded processing. Ported from Delphi VCL to Lazarus LCL.

Features:
- Encrypt and decrypt files with any cipher + hash combination
- Threaded encryption with progress bar
- Drag-and-drop file support
- OnProgressEvent callback for real-time progress display

## Requirements

- **Lazarus IDE** 2.0 or later (includes `lazbuild`)
- **Free Pascal Compiler (FPC)** 3.2.0 or later
- **GTK2** development libraries (Linux only)

### Linux (Debian/Ubuntu)

```bash
sudo apt-get install lazarus libgtk2.0-dev
```

### Linux (Fedora/RHEL)

```bash
sudo dnf install lazarus gtk2-devel
```

### Linux (Arch)

```bash
sudo pacman -S lazarus gtk2
```

### Windows / macOS

No additional dependencies beyond Lazarus.

## Build

### Using lazbuild (command line)

From the project root:

```bash
lazbuild examples/gui/FileEncrypt/EncryptFileUsingThread.lpi
```

### Using Makefile

From the project root:

```bash
make build-gui
```

### Using Lazarus IDE

1. Open `EncryptFileUsingThread.lpi` in Lazarus
2. Click **Run > Build** (or press Shift+F9)

## Project files

| File | Description |
|------|-------------|
| `EncryptFileUsingThread.lpi` | Lazarus project file |
| `EncryptFileUsingThread.lpr` | Program source |
| `uMain.pas` | Main form unit (encryption thread logic) |
| `uMain.lfm` | Main form layout |
| `UnitUtilitaires.pas` | Utility functions |

## Cleanup

```bash
make clean-examples
```
