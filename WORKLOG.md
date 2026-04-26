# Active Work
Project: /home/the_bomb/icopykey
Task: icopyzed package — unified src/ layout, pip install, single command
Status: completed
Updated: 2026-04-26

## Completed (current session)
- [x] Created comprehensive TEST_PLAN.md
- [x] Rewrote CLI as modular package (10 files, 111 tests)
- [x] Folded Crypto1 LFSR cipher from core/mifare_crypto.py into cli/operations.py
- [x] Restructured to src/icopykey/{cli,x100}/ single-package layout
- [x] Unified dispatcher: icopyzed (interactive) + decrypt + convert subcommands
- [x] Created pyproject.toml: pip install -e . / pipx install icopyzed
- [x] Dropped dead code: core/, config/, updater/, gui/ (not imported at runtime)
- [x] 115 tests pass under installed package (111 CLI + 4 x100)
- [x] icopyzed --help, icopyzed decrypt --demo, icopyzed convert all work

## Completed (current session)
- [x] Created comprehensive TEST_PLAN.md (8 sections, 5 phases, 57 test steps, 12 success criteria)
- [x] Analyzed web app at http://app.copykey.hyctec.cn/Soft/ (download portal for CopyKEY Manager)
- [x] Phase 1: Foundation modules — errors, validators, config, logger, display, progress (6 files)
- [x] Phase 2: Commands + Menus — commands.py (16 handlers), menus.py (4 sub-menus)
- [x] Phase 3: Main CLI rewrite — copykey_cli.py (argparse + interactive loop, ~200 lines vs 1406)
- [x] Phase 4: Tests + Docs — 4 test files (111 tests), README.md, requirements.txt updated
- [x] All 115 tests pass (111 CLI + 4 x100_decrypt)
- [x] Syntax check passes on all 10 new/modified files
- [x] Added `rich` to requirements.txt (optional dependency)

### New files created (12)
cli/errors.py, cli/validators.py, cli/config_manager.py, cli/logger_setup.py,
cli/display.py, cli/progress.py, cli/operations.py, cli/commands.py,
cli/menus.py, cli/README.md, cli/tests/test_validators.py, cli/tests/test_commands.py,
cli/tests/test_config.py, cli/tests/test_display.py, TEST_PLAN.md

### Files replaced
cli/copykey_cli.py (1406 LOC monolithic → modular rewrite)

## Completed (prior session)
- [x] test_core.py imports fixed (format_strategies → strategies)
- [x] Deleted 5 redundant docs (kept ANALYSIS.md as canonical)
- [x] All 4 tests pass
- [x] x100_decrypt deduplication — removed format_strategies.py + strategies.py, updated all imports
- [x] mifare_crypto.py — Crypto1 LFSR, keystream, MifareSector/MifareCard dataclasses
- [x] card_encryption.py — sector/card encryption with key strategies
- [x] key_vault.py — PBKDF2+AES-GCM encrypted key storage (class: LocalKeyVault)
- [x] Document consolidation — 5 redundant docs merged into canonical ANALYSIS.md
