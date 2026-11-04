# Green Self-Healing Compiler Documentation

> **v2.0:** the detection, classification, security and optimisation layers were rebuilt - see `OPTIMIZATION.md` and `CHANGELOG.md`. Where this document describes the 37 MB scikit-learn model, regex security scan, or per-error compilation, the v2.0 design replaces it.


## Overview

This project is a C++ analysis and repair tool with two main entry points:

- A CLI analyzer that compiles a C++ source file, parses diagnostics, enriches each error with explanations and suggestions, and can emit JSON.
- A PyQt6 desktop GUI that combines code editing, compile/run flows, AST exploration, energy telemetry, a function call graph, and an auto-heal loop.

The overall goal is to move from plain compiler output toward a self-healing, energy-aware workflow for C++ code.

## Key Capabilities

- Compile C++ source with `g++ -std=c++17`
- Parse compiler errors and warnings into structured records
- Classify errors using a trained or fallback classifier
- Attach readable explanations, suggestions, and basic security risk labels
- Extract and visualize a filtered Clang AST for the user source
- Run the compiled binary from the GUI
- Attempt automated repairs through a bounded auto-heal loop
- Track execution-related energy/carbon telemetry in the GUI
- Visualize a lightweight function/module call graph for the current C++ source

## Repository Layout

- `src/main.py`: CLI entry point for analysis
- `src/gui.py`: PyQt6 desktop application
- `src/compiler_runner.py`: `g++` invocation and raw diagnostic capture
- `src/error_parser.py`: compiler diagnostic parsing into structured error models
- `src/error_explainer.py`: explanation, suggestion, and security-risk enrichment
- `src/error_classifier.py`: ML-backed error classification
- `src/ast_extractor.py`: filtered Clang AST extraction and tree parsing
- `src/heal_loop.py`: auto-heal orchestration loop
- `src/auto_healer.py`: patch-generation logic for fixable errors
- `src/diff_viewer.py`: diff generation and HTML formatting for GUI display
- `src/common_errors.py`: curated glossary of common compiler issues
- `data/`: training data and serialized classifier artifacts
- `test_cases/`: sample or training-oriented C++ error cases
- `file.cpp`: current working example source file in the repo root

## Requirements

Python dependencies are listed in `requirements.txt`:

- `PyQt6>=6.4.0`
- `scikit-learn>=1.2.0`
- `joblib>=1.2.0`
- `codecarbon>=2.3.0`

System tools expected by the project:

- `g++`
- `clang++`

The GUI assumes a local desktop environment. On macOS, running the GUI requires access to windowing services.

## Installation

Install Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Make sure `g++` and `clang++` are available:

```bash
g++ --version
clang++ --version
```

## CLI Usage

Analyze a source file:

```bash
python3 src/main.py file.cpp
```

Useful flags:

- `-j`, `--json`: emit structured JSON
- `-v`, `--verbose`: include code context
- `-c`, `--context`: number of context lines

Example:

```bash
python3 src/main.py file.cpp -j -v
```

### CLI Flow

`src/main.py` performs the following steps:

1. Compile the source file with `g++`
2. Parse compiler diagnostics
3. Extract a filtered AST from Clang
4. Attach nearest AST-node context to each error
5. Enrich each error with:
   - explanation
   - suggestion
   - category
   - confidence
   - basic security-risk assessment
6. Print human-readable output or JSON

## GUI Usage

Launch the desktop application:

```bash
python3 src/gui.py
```

### Main GUI Features

- Load and edit a C++ file
- Compile/analyze the current file
- Run the built binary
- View parsed compiler feedback
- Trigger auto-heal attempts
- Inspect AST structure
- Monitor energy/carbon telemetry
- View a function/module relationship graph

### Sidebar Pages

#### Page 1: Editor and Analysis Workspace

This is the primary working area.

- Left side: code editor
- Right side: diagnostics, suggestions, diffs, and terminal/process output
- Toolbar actions:
  - load file
  - compile
  - run code
  - auto-heal

#### Page 2: AST Explorer

This page displays a filtered tree view of the user source AST.

- Data comes from `src/ast_extractor.py`
- Standard-library/internal AST noise is filtered out
- The tree focuses on declarations, statements, expressions, and recovery nodes relevant to the user file

#### Page 3: Energy Dashboard

This page shows energy-related telemetry and a visual graph.

Displayed metrics:

- Power usage
- Carbon intensity
- Execution time
- RAPL availability/reading

Behavior:

- Uses CodeCarbon when available
- Falls back to animated placeholder telemetry when CodeCarbon has not yet produced a meaningful sample
- Uses smaller units so tiny workloads remain visible:
  - `mW`
  - `mgCO2/Wh`

RAPL notes:

- Linux systems with `/sys/class/powercap` can expose RAPL counters
- On macOS, RAPL will typically show as unavailable

#### Page 4: Function Call Graph

This page draws a lightweight static relationship graph for the currently loaded C++ source.

It shows:

- detected function definitions
- internal function-to-function calls
- sampled external/library calls
- included modules/headers

The graph is heuristic-based and built from regex/static parsing in `src/gui.py`.

## AST Extraction Design

`src/ast_extractor.py` is optimized for the GUI tree view.

Important design choices:

- Uses `clang++ -Xclang -ast-dump -fsyntax-only`
- Streams output rather than loading the full dump into memory
- Filters AST subtrees to the user file
- Handles both explicit file locations and Clang relative locations like `<line:...>`
- Trims noisy details such as pointer addresses
- Builds a compact nested dictionary structure for the GUI tree widgets

This keeps the AST usable for normal C++ files even when standard-library headers are present.

## Error Explanation Pipeline

`src/error_explainer.py` combines three sources of intelligence:
 
- A glossary of curated common errors
- An ML classifier from `src/error_classifier.py`
- Regex fallbacks for low-confidence cases

Each error may receive:

- a structured explanation
- a practical suggestion
- a category and confidence score
- a simple security risk label and reason

## Auto-Heal Loop

`src/heal_loop.py` coordinates the repair workflow:

1. Compile the current file
2. Parse and classify errors
3. Select the first fixable error
4. Ask `auto_healer.attempt_fix()` for a patch
5. Write the patched file
6. Recompile
7. Repeat up to `MAX_ATTEMPTS = 10`

If repair fails after the attempt limit, the GUI presents guidance options such as:

- edit manually
- skip the error
- provide a hint and retry

## Energy Telemetry Design

The GUI’s energy telemetry is intentionally pragmatic.

- CodeCarbon is used for estimated CPU/RAM/emissions tracking
- The app disables macOS `powermetrics` probing to avoid blocking on password prompts
- Forced CPU/RAM power values are used when needed so the UI remains functional
- A placeholder fluctuating signal is shown until real samples become meaningful

This means the energy page is optimized for responsiveness and visibility, not for scientific-grade measurement.

## Limitations

- Compiler integration is currently single-file oriented
- The call graph is heuristic and not a full semantic graph
- Auto-heal only fixes categories supported by `auto_healer.py`
- Energy telemetry on macOS is estimated rather than hardware-precise
- The GUI currently depends on local desktop access and does not run as a web app
- Serialized ML models may emit version warnings if the local `scikit-learn` version differs from the training version

## Typical Workflow

1. Open the GUI with `python3 src/gui.py`
2. Load or edit a C++ file
3. Click compile to inspect errors and suggestions
4. Review AST on page 2 if structural context is useful
5. Review telemetry on page 3
6. Review source relationships on page 4
7. Trigger auto-heal if the issue is fixable
8. Run the compiled binary and validate behavior

## Troubleshooting

### `g++ compiler not found`

Install a C++ toolchain and ensure `g++` is on `PATH`.

### AST extraction fails

Ensure `clang++` is installed and available on `PATH`.

### GUI starts but shows model warnings

The current serialized classifier artifacts were built with an older `scikit-learn` version. The warning does not necessarily prevent the app from running, but predictions may differ from the original training environment.

### Energy page appears static

The app now shows placeholder telemetry until CodeCarbon emits a meaningful sample. If it still looks flat, restart the GUI and confirm that CodeCarbon is installed in the same Python environment used to launch `src/gui.py`.

## Future Improvement Areas

- Multi-file/project-level compilation and healing
- Stronger semantic and logical bug detection
- More accurate energy measurement on supported platforms
- Persistent repair history and learning from prior successful fixes
- Sandboxed execution for untrusted binaries
- Richer AST/call-graph interactions across files

## Diagnostics Parsing (compiler *and* linker)

All g++ invocations go through `src/diagnostics.py`, the single source of truth
for turning raw stderr into diagnostics. It recognises front-end diagnostics
(`file:line:col: error: ...`) **and** GNU ld / macOS ld linker failures
(`undefined reference to ...`, `multiple definition of ...`, `collect2: error`),
forces the `C` locale so messages are always English with ASCII quotes, writes
build output to a private temp directory (no stray `a.out`), and guarantees that
a non-zero compiler exit code can never be reported as "Compilation successful".

## Input Safety Gate

`compiler_runner._sanitize_code()` is a layered, best-effort guard (not a
sandbox): (1) lexical scan of comment/string-stripped source, (2) the same scan
on macro-expanded code (`g++ -E`, user lines only), (3) a check that the compiled
object has no undefined references to `system`, `popen`, `exec*`, `fork`,
`dlopen`, `dlsym`, `syscall`, ... Aliasing (`auto p = &system;`) and macro
renaming (`#define RUN system`) are therefore blocked. Code that must genuinely
run untrusted programs still needs a real sandbox. Use `ALLOW_SYSTEM_CALLS=1`,
`ALLOW_ASSEMBLY=1`, `ALLOW_SYS_INCLUDES=1` to relax individual checks.

## Tests and Evaluation

```bash
python3 tests/test_audit_fixes.py   # regression tests for the v1 audit findings
python3 tests/evaluate.py           # reproduces the heal-loop / security numbers in PBL_Report.md
```
Set `GSC_DISABLE_DATASET_LOGGING=1` to stop the CLI from appending to
`data/training_data.json` (the test scripts do this automatically).

