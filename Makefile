# ==============================================================================
# DCPcrypt Makefile
# Build, test and cleanup
# Cross-platform: Linux, macOS, Windows (MSYS2/MinGW)
# ==============================================================================

.PHONY: all build build-examples build-console build-gui build-all rebuild \
        test check clean clean-examples clean-all help info

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

SRCDIR := src
TESTDIR := tests
EXDIR := examples
FPCFLAGS := -Mdelphi -FE$(TESTDIR) -Fu$(SRCDIR) -Fu$(SRCDIR)/Ciphers -Fu$(SRCDIR)/Hashes -Fu$(TESTDIR)
FPCFLAGS_EX := -Mdelphi -Fu$(SRCDIR) -Fu$(SRCDIR)/Ciphers -Fu$(SRCDIR)/Hashes

# Test programs
TESTS := test_hashes test_ciphers test_block_modes test_base64 test_stream_encrypt

# Console examples
CONSOLE_EXAMPLES := demo_encrypt_string demo_file_encrypt

# GUI examples
GUI_EXAMPLES := \
	$(EXDIR)/gui/EncryptStrings/EncryptStringsViaEncryptStream.lpi \
	$(EXDIR)/gui/FileEncrypt/EncryptFileUsingThread.lpi

# Detect OS for binary extension
ifeq ($(OS),Windows_NT)
  EXE := .exe
else
  EXE :=
endif

# ==============================================================================
# HELP (Default target)
# ==============================================================================

help:
	@echo "==============================================================================="
	@echo "DCPcrypt Makefile"
	@echo "==============================================================================="
	@echo ""
	@echo "BUILD:"
	@echo "  make build            - Compile all test programs"
	@echo "  make build-examples   - Compile all examples (console + GUI)"
	@echo "  make build-console    - Compile console examples"
	@echo "  make build-gui        - Compile GUI examples (requires lazbuild)"
	@echo "  make build-all        - Compile everything (tests + examples)"
	@echo "  make rebuild          - Clean and rebuild tests"
	@echo ""
	@echo "TEST:"
	@echo "  make test             - Build and run all tests"
	@echo ""
	@echo "VERIFY:"
	@echo "  make check            - Full verification (clean, build, test)"
	@echo "  make info             - Show project information"
	@echo ""
	@echo "CLEANUP:"
	@echo "  make clean            - Remove compiled test binaries and objects"
	@echo "  make clean-examples   - Clean examples/ build artifacts"
	@echo "  make clean-all        - Clean tests, examples and source build artifacts"
	@echo ""
	@echo "==============================================================================="

# ==============================================================================
# BUILD TARGETS
# ==============================================================================

build:
	@echo "==============================================================================="
	@echo "Building DCPcrypt tests..."
	@echo "==============================================================================="
	@echo ""
	@fail=0; \
	for test in $(TESTS); do \
		echo ">>> Compiling $$test.lpr ..."; \
		if fpc $(FPCFLAGS) $(TESTDIR)/$$test.lpr > /dev/null 2>&1; then \
			echo "  [OK] $$test"; \
		else \
			echo "  [FAIL] $$test"; \
			fpc $(FPCFLAGS) $(TESTDIR)/$$test.lpr 2>&1 | tail -5; \
			fail=$$((fail + 1)); \
		fi; \
		echo ""; \
	done; \
	if [ $$fail -ne 0 ]; then \
		echo "[FAIL] $$fail program(s) failed to compile."; \
		exit 1; \
	fi
	@echo "[OK] All test programs compiled!"

build-console:
	@echo "==============================================================================="
	@echo "Building console examples..."
	@echo "==============================================================================="
	@echo ""
	@fail=0; \
	for ex in $(CONSOLE_EXAMPLES); do \
		echo ">>> Compiling $$ex.lpr ..."; \
		if fpc $(FPCFLAGS_EX) -FE$(EXDIR)/console $(EXDIR)/console/$$ex.lpr > /dev/null 2>&1; then \
			echo "  [OK] $$ex"; \
		else \
			echo "  [FAIL] $$ex"; \
			fpc $(FPCFLAGS_EX) -FE$(EXDIR)/console $(EXDIR)/console/$$ex.lpr 2>&1 | tail -5; \
			fail=$$((fail + 1)); \
		fi; \
		echo ""; \
	done; \
	if [ $$fail -ne 0 ]; then \
		echo "[FAIL] $$fail example(s) failed to compile."; \
		exit 1; \
	fi
	@echo "[OK] All console examples compiled!"

build-gui:
	@echo "==============================================================================="
	@echo "Building GUI examples (requires lazbuild)..."
	@echo "==============================================================================="
	@echo ""
	@if ! command -v lazbuild > /dev/null 2>&1; then \
		echo "[SKIP] lazbuild not found. Install Lazarus IDE to build GUI examples."; \
		exit 0; \
	fi; \
	fail=0; \
	for lpi in $(GUI_EXAMPLES); do \
		name=$$(basename "$$(dirname "$$lpi")"); \
		echo ">>> Building $$name ..."; \
		if lazbuild "$$lpi" > /dev/null 2>&1; then \
			echo "  [OK] $$name"; \
		else \
			echo "  [FAIL] $$name"; \
			lazbuild "$$lpi" 2>&1 | tail -5; \
			fail=$$((fail + 1)); \
		fi; \
		echo ""; \
	done; \
	if [ $$fail -ne 0 ]; then \
		echo "[FAIL] $$fail GUI example(s) failed to compile."; \
		exit 1; \
	fi
	@echo "[OK] All GUI examples compiled!"

build-examples: build-console build-gui

build-all: build build-examples
	@echo ""
	@echo "==============================================================================="
	@echo "[OK] All builds complete!"
	@echo "==============================================================================="

rebuild: clean build

# ==============================================================================
# TEST TARGETS
# ==============================================================================

test: build
	@echo ""
	@echo "==============================================================================="
	@echo "Running DCPcrypt tests..."
	@echo "==============================================================================="
	@pass=0; fail=0; total=0; \
	for test in $(TESTS); do \
		total=$$((total + 1)); \
		echo ""; \
		echo ">>> $$test"; \
		echo "-------------------------------------------------------------------------------"; \
		if $(TESTDIR)/$$test$(EXE); then \
			pass=$$((pass + 1)); \
		else \
			fail=$$((fail + 1)); \
		fi; \
	done; \
	echo ""; \
	echo "==============================================================================="; \
	echo "Suite Summary: $$pass/$$total passed, $$fail failed"; \
	echo "==============================================================================="; \
	if [ $$fail -ne 0 ]; then exit 1; fi

# ==============================================================================
# VERIFICATION
# ==============================================================================

check: clean build test
	@echo ""
	@echo "==============================================================================="
	@echo "[OK] Full verification passed!"
	@echo "==============================================================================="

info:
	@echo "==============================================================================="
	@echo "DCPcrypt Project Information"
	@echo "==============================================================================="
	@echo ""
	@echo "Source files:"
	@echo "  Cipher units:  $$(ls $(SRCDIR)/Ciphers/*.pas 2>/dev/null | wc -l)"
	@echo "  Hash units:    $$(ls $(SRCDIR)/Hashes/*.pas 2>/dev/null | wc -l)"
	@echo "  Core units:    $$(ls $(SRCDIR)/*.pas 2>/dev/null | wc -l)"
	@echo ""
	@echo "Test programs:"
	@echo "  Test files:    $$(ls $(TESTDIR)/*.lpr 2>/dev/null | wc -l)"
	@echo "  Shared units:  $$(ls $(TESTDIR)/*.pas 2>/dev/null | wc -l)"
	@echo ""
	@echo "Examples:"
	@echo "  Console:       $$(ls $(EXDIR)/console/*.lpr 2>/dev/null | wc -l)"
	@echo "  GUI:           $$(ls $(EXDIR)/gui/*//*.lpi 2>/dev/null | wc -l)"
	@echo ""
	@echo "Platform: $$(uname -s 2>/dev/null || echo Windows) ($$(uname -m 2>/dev/null || echo unknown))"
	@echo "FPC version: $$(fpc -iV 2>/dev/null || echo 'not found')"
	@echo "Lazarus version: $$(lazbuild --version 2>/dev/null | head -1 || echo 'not found')"
	@echo "==============================================================================="

# ==============================================================================
# CLEANUP TARGETS
# ==============================================================================

clean:
	@echo "Cleaning tests/..."
	@for test in $(TESTS); do \
		rm -f $(TESTDIR)/$$test $(TESTDIR)/$$test.exe; \
	done
	@rm -f $(TESTDIR)/*.o $(TESTDIR)/*.ppu $(TESTDIR)/*.compiled \
		$(TESTDIR)/*.rst $(TESTDIR)/*.rsj $(TESTDIR)/*.or 2>/dev/null || true
	@rm -f $(TESTDIR)/link*.res 2>/dev/null || true
	@echo "  [OK] tests/ cleaned."

clean-examples:
	@echo "Cleaning examples/..."
	@rm -f $(EXDIR)/console/demo_encrypt_string $(EXDIR)/console/demo_encrypt_string.exe \
		$(EXDIR)/console/demo_file_encrypt $(EXDIR)/console/demo_file_encrypt.exe 2>/dev/null || true
	@rm -f $(EXDIR)/gui/EncryptStrings/EncryptStringsViaEncryptStream \
		$(EXDIR)/gui/EncryptStrings/EncryptStringsViaEncryptStream.exe \
		$(EXDIR)/gui/FileEncrypt/EncryptFileUsingThread \
		$(EXDIR)/gui/FileEncrypt/EncryptFileUsingThread.exe 2>/dev/null || true
	@find $(EXDIR) -type f \( -name "*.o" -o -name "*.ppu" -o -name "*.compiled" \
		-o -name "*.rst" -o -name "*.rsj" -o -name "*.or" -o -name "link*.res" \
		-o -name "*.bak" -o -name "*~" \) -delete 2>/dev/null || true
	@find $(EXDIR) -type d -name "lib" -exec rm -rf {} + 2>/dev/null || true
	@echo "  [OK] examples/ cleaned."

clean-all: clean clean-examples
	@echo "Cleaning src/ build artifacts..."
	@find $(SRCDIR) -type f \( -name "*.o" -o -name "*.ppu" -o -name "*.compiled" \
		-o -name "*.rst" -o -name "*.rsj" -o -name "*.or" -o -name "link*.res" \) -delete 2>/dev/null || true
	@find $(SRCDIR) -type d -name "lib" -exec rm -rf {} + 2>/dev/null || true
	@echo "  [OK] src/ cleaned."
	@echo ""
	@echo "[OK] All directories cleaned!"
