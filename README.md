# zwc-decompile

Static forensic decompiler for zsh `.zwc` files.

`zwc-decompile` parses zsh wordcode containers and reconstructs source-like zsh text **without invoking zsh, sourcing the input, or executing recovered code**.

The primary use case is DFIR: inspecting compiled zsh startup files, autoloaded functions, function digests, and other `.zwc` artifacts when the original shell source is missing, has been modified, or should not be trusted.

> [!IMPORTANT]
> The output is a **semantic reconstruction**, not the original source file. zsh wordcode does not preserve comments or the original whitespace/layout, so those cannot be recovered exactly.

## Why this exists

zsh can precompile scripts and functions with the `zcompile` builtin. The resulting files use the `.zwc` extension, short for **zsh word code**.

Examples include:

```text
.zshrc.zwc
.zprofile.zwc
functions.zwc
completion.zwc
some-function.zwc
```

From a forensic perspective, these files matter because a compiled artifact may continue to contain useful executable semantics even when an investigator only reviews the corresponding plaintext shell files.

A simple workflow such as:

```bash
find ~ -name '*.zwc' -type f
```

can therefore reveal artifacts that deserve separate analysis.

The problem is that `.zwc` is an internal compiled representation rather than a normal shell script. `zwc-decompile` provides a static way to inspect that representation and recover readable, source-like zsh.

## Features

- Parses zsh `.zwc` containers statically.
- Does **not** execute the input.
- Detects little- and big-endian ZWC images.
- Reads container metadata and embedded zsh version information.
- Enumerates multiple entries in digest files.
- Reconstructs zsh control flow and shell syntax from wordcode.
- Extracts the embedded string table.
- Produces human-readable output or JSON.
- Can write reconstructed entries to individual `.zsh` files.
- Supports entry filtering.
- Provides a word-by-word decoder trace.
- Tracks decoder coverage and reports unconsumed wordcode.
- Offers a strict mode for validation-oriented workflows.
- Includes built-in regression tests.
- Computes the SHA-256 hash of the analyzed input.

The decoder currently targets the **zsh 5.9 wordcode/dump layout**. Files sharing the same container magic may still be attempted, but the tool warns when the embedded version differs from the validated target.

## Safety model

The tool is intentionally designed for static analysis.

It does **not**:

- run the `.zwc` file;
- invoke `zsh`;
- `source` recovered code;
- execute commands reconstructed from the file;
- load functions from the analyzed artifact.

This matters when investigating potentially malicious shell artifacts.

You should still treat reconstructed output as untrusted text and avoid executing it unless you have independently reviewed it.

## Requirements

- Python 3
- No third-party Python packages

The implementation uses only the Python standard library.

## Installation

Clone the repository:

```bash
git clone https://github.com/malmoeb/zwc-decompile.git
cd zwc-decompile
```

Make the script executable:

```bash
chmod +x zwc-decompile.py
```

Run the built-in tests:

```bash
python3 zwc-decompile.py --self-test
```

Expected result:

```text
[+] all built-in decoder tests passed
```

## Quick start

Analyze a compiled zsh file:

```bash
python3 zwc-decompile.py ~/.zshrc.zwc
```

or:

```bash
./zwc-decompile.py ~/.zshrc.zwc
```

The metadata summary is written to `stderr`, while reconstructed entries are written to `stdout`.

Example structure:

```text
=== ZWC STATIC DECOMPILER ===
File:        /Users/example/.zshrc.zwc
SHA256:      ...
zsh version: 5.9
Byte order:  little
Mode:        mapped
Entries:     1

# ===== ZWC ENTRY 0: /Users/example/.zshrc =====
# wordcode=... words, strings=... bytes, semantic-walk=complete, raw-consumed=...%
...
```

## Usage

```text
usage: zwc-decompile.py [-h] [--entry ENTRY] [--json] [--strings]
                        [--min-string MIN_STRING] [--trace]
                        [--indent INDENT] [--output-dir OUTPUT_DIR]
                        [--strict] [--self-test]
                        [zwc]
```

### Command-line options

| Option | Description |
| --- | --- |
| `zwc` | Compiled zsh `.zwc` file to analyze. |
| `--entry ENTRY` | Analyze only an entry whose name contains the supplied value, or select an entry by numeric index. |
| `--json` | Emit machine-readable JSON. |
| `--strings` | Include decoded strings from the entry's string table. |
| `--min-string N` | Minimum rendered string length reported by `--strings`. Default: `3`. |
| `--trace` | Include a word-by-word parser/decoder consumption trace. |
| `--indent N` | Number of spaces per reconstructed indentation level. Default: `4`. |
| `--output-dir DIR` | Write each reconstructed entry to an individual `.reconstructed.zsh` file. |
| `--strict` | Treat remaining non-zero, unconsumed wordcode as a decompilation failure. |
| `--self-test` | Run the built-in regression tests and exit. |

## Common forensic workflows

### 1. Reconstruct a single `.zwc`

```bash
python3 zwc-decompile.py suspect.zwc
```

This prints metadata followed by reconstructed zsh.

### 2. Extract the string table as well

```bash
python3 zwc-decompile.py suspect.zwc --strings
```

This is useful when full semantic reconstruction fails or when you want a fast view of embedded paths, commands, URLs, function names, variable names, and other textual material.

Example:

```text
# ----- STRING TABLE -----
# str+0x0000  curl
# str+0x0005  https://example.invalid/payload
# str+0x0025  /tmp/update
```

The presence of a string is evidence that it exists in the compiled artifact. It does not, by itself, prove that the corresponding code path executed.

### 3. Lower or raise the minimum string length

```bash
python3 zwc-decompile.py suspect.zwc --strings --min-string 6
```

### 4. Produce JSON for automation

```bash
python3 zwc-decompile.py suspect.zwc --json > report.json
```

The JSON report includes:

- file path;
- file size;
- SHA-256;
- embedded zsh version;
- byte order;
- mapped/read mode;
- opposite-byte-order image information;
- entry metadata;
- reconstructed source;
- decompilation errors;
- semantic-walk coverage;
- optional strings;
- optional decoder trace.

Example with `jq`:

```bash
python3 zwc-decompile.py suspect.zwc --json \
  | jq '.entries[] | {name, error, coverage, decompiled}'
```

### 5. Extract every entry from a digest

A `.zwc` file can contain more than one compiled function or script entry.

```bash
python3 zwc-decompile.py functions.zwc --output-dir recovered/
```

Example output:

```text
recovered/
├── function-one.reconstructed.zsh
├── function-two.reconstructed.zsh
└── function-three.reconstructed.zsh
```

The filenames are sanitized before being written.

### 6. Select one entry

By name:

```bash
python3 zwc-decompile.py functions.zwc --entry update_check
```

By numeric index:

```bash
python3 zwc-decompile.py functions.zwc --entry 3
```

### 7. Inspect decoder coverage

Each reconstructed entry contains coverage information such as:

```text
# wordcode=121 words, strings=342 bytes, semantic-walk=complete, raw-consumed=98.35%
```

`semantic-walk=complete` means the decoder visited every non-zero wordcode word that should be part of the semantic traversal.

Some zero-valued `WC_END` words can remain unconsumed because they are structural sentinels. The tool reports those separately instead of incorrectly treating them as a decoding failure.

### 8. Use strict mode

```bash
python3 zwc-decompile.py suspect.zwc --strict
```

In strict mode, an entry fails if non-zero wordcode remains unreachable after reconstruction.

This is useful for:

- regression testing;
- parser development;
- validating support for unfamiliar artifacts;
- identifying files whose layout may not match the expected zsh version.

### 9. Generate a detailed wordcode trace

```bash
python3 zwc-decompile.py suspect.zwc --trace
```

The trace records:

- program-counter position;
- raw 32-bit word;
- parser role;
- decoded opcode where applicable;
- opcode data;
- explicit parser jumps.

This is primarily intended for debugging, format research, and validation rather than routine triage.

### 10. Combine trace, strings, and JSON

```bash
python3 zwc-decompile.py suspect.zwc \
  --json \
  --strings \
  --trace \
  > full-report.json
```

## Creating a test `.zwc`

If zsh is installed, you can create a benign test file yourself.

Create a script:

```bash
cat > demo.zsh <<'EOF'
print "hello from zwc"

if [[ -f /tmp/example ]]; then
    print "file exists"
else
    print "file does not exist"
fi
EOF
```

Compile it:

```bash
zsh -c 'zcompile demo.zsh'
```

This creates:

```text
demo.zsh.zwc
```

Now reconstruct it:

```bash
python3 zwc-decompile.py demo.zsh.zwc
```

You can also ask zsh to inspect the compiled container:

```bash
zsh -c 'zcompile -t demo.zsh.zwc'
```

## What the tool reconstructs

The decoder walks the zsh wordcode representation rather than simply running `strings` over the file.

It contains handling for the major wordcode structures used by zsh, including:

- lists and sublists;
- `&&` and `||`;
- negation;
- coprocess forms;
- pipelines;
- redirections;
- scalar and array assignments;
- simple commands;
- `typeset`-style commands;
- subshell groups;
- current-shell groups;
- `time`;
- function definitions;
- `for`;
- `select`;
- `while`;
- `until`;
- `repeat`;
- `case`;
- `if` / `elif` / `else`;
- conditional expressions;
- arithmetic expressions;
- autoload-related function structures;
- `try` structures supported by the target wordcode layout.

The reconstruction logic follows the semantics of zsh's internal wordcode traversal rather than trying to infer shell syntax from arbitrary byte sequences.

## Container parsing

The parser validates and exposes several parts of the `.zwc` container:

- ZWC magic;
- byte order;
- container flags;
- zsh version string;
- header length;
- entry descriptors;
- entry start offset;
- entry length;
- pattern count;
- string-table offset;
- load style;
- tail offset;
- optional opposite-byte-order image.

zsh may store compiled data in a form suitable for systems with different byte orders. `zwc-decompile` detects the primary byte order and also sanity-checks the secondary image when present.

## String decoding

zsh does not store every string as plain ASCII or UTF-8.

The decoder includes handling for zsh's internal tokenized character representation and `Meta` encoding so that reconstructed text and forensic strings are rendered into a more useful form.

Invalid UTF-8 is preserved using escaped byte representations instead of causing the analysis to abort.

## Exit codes

The current CLI uses the following practical exit behavior:

| Exit code | Meaning |
| ---: | --- |
| `0` | Analysis completed and no selected entry had a decompilation error. |
| `1` | File/container error, invalid input, failed self-test, or no matching entry. |
| `2` | One or more selected entries could not be semantically reconstructed. |

When `--strict` is used, incomplete semantic coverage can turn an otherwise reconstructed entry into an error.

## Forensic interpretation

A reconstructed `.zwc` should be treated as one artifact within a wider investigation.

Useful questions include:

- Does a `.zshrc.zwc` exist even though `.zshrc` is absent?
- Is the `.zwc` newer than the plaintext source?
- Do the plaintext and compiled forms contain different commands?
- Does the compiled file contain network destinations not present in current shell configuration?
- Are there unexpected persistence commands or environment modifications?
- Are functions present in a digest that do not exist as source files anymore?
- Do timestamps indicate the compiled artifact predates or postdates suspected compromise activity?
- Does shell history show `zcompile`, `zrecompile`, or manipulation of startup files?
- Are there related artifacts in `.zprofile`, `.zshenv`, `.zlogin`, function directories, or custom `$fpath` locations?

Do not rely on the reconstructed text alone to prove execution. Correlate with other evidence such as:

- filesystem timestamps;
- FSEvents;
- shell history;
- Unified Logs;
- Endpoint Security telemetry;
- EDR process events;
- network telemetry;
- persistence artifacts;
- file download/quarantine metadata;
- user activity.

## Important limitations

### The original source cannot be recovered byte-for-byte

Compilation discards information that is not necessary for execution.

In particular, the tool cannot reliably recover:

- comments;
- original whitespace;
- original indentation;
- exact line breaks;
- some purely syntactic presentation choices.

Two different source files can therefore compile into semantically equivalent wordcode and reconstruct to the same or very similar output.

### Output is source-like, not source-identical

The reconstructed text is intended to preserve meaning and control flow, not formatting.

Do not use the output for source-code provenance claims based solely on whitespace, comments, or formatting.

### Version coupling

The implementation is validated against the zsh 5.9 wordcode/dump layout.

If a file reports another version, the tool prints a warning and attempts parsing only where the container is compatible.

A successful parse of an unvalidated version should still be treated cautiously.

### Corruption and malformed inputs

The parser performs bounds checks and structural validation, but `.zwc` is an internal implementation format rather than a stable interchange format.

Corrupt, truncated, intentionally malformed, or version-incompatible files can fail to decode.

### Reconstruction does not prove execution

Code present in a `.zwc` may never have executed.

Likewise, a function stored in a multi-entry digest may never have been loaded.

Execution requires correlation with runtime evidence.

### String-table hits need context

Strings can belong to inactive branches, unused functions, variable values, redirection targets, or other structures.

Use the semantic reconstruction whenever possible.

## Validation

Run the built-in regression tests:

```bash
python3 zwc-decompile.py --self-test
```

The current self-test suite exercises at least:

- a simple command;
- a `typeset`/assignment structure;
- a named function definition;
- semantic-walk coverage expectations.

Before publishing major parser changes, additional test fixtures should be generated from known zsh source and compared against expected reconstruction.

## Suggested repository layout

```text
zwc-decompile/
├── README.md
├── LICENSE
├── zwc-decompile.py
├── tests/
│   ├── fixtures/
│   └── README.md
└── examples/
    └── README.md
```

A minimal initial release can start with only:

```text
README.md
zwc-decompile.py
LICENSE
```

## Development notes

The implementation is intentionally dependency-free.

Useful development checks:

```bash
python3 zwc-decompile.py --self-test
python3 -m py_compile zwc-decompile.py
```

For a fixture-based test, compile a known source file and compare the reconstructed output:

```bash
zsh -c 'zcompile test.zsh'
python3 zwc-decompile.py test.zsh.zwc
```

When adding support for new wordcode behavior, prefer a small reproducible source fixture that exercises exactly that construct.

## Implementation background

The textual reconstruction engine is based on the layout and traversal behavior described by the zsh source, particularly the structures and logic around:

- `Src/zsh.h`
- `Src/parse.c`
- `Src/text.c`
- `getpermtext()`
- `gettext2()`

The goal is to reproduce the relevant decoding semantics in Python while keeping analysis static and independent from the target `.zwc` at runtime.

This project is not part of, endorsed by, or maintained by the zsh project.

## zsh references

Official documentation:

- zsh manual — `zcompile`:
  https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html
- zsh manual — files and compiled startup files:
  https://zsh.sourceforge.io/Doc/Release/Files.html
- zsh manual — functions and compiled function lookup:
  https://zsh.sourceforge.io/Doc/Release/Functions.html

Upstream source:

- zsh source mirror:
  https://github.com/zsh-users/zsh
- zsh licence:
  https://github.com/zsh-users/zsh/blob/master/LICENCE
- `Src/text.c`:
  https://github.com/zsh-users/zsh/blob/master/Src/text.c
- `Src/parse.c`:
  https://github.com/zsh-users/zsh/blob/master/Src/parse.c
- `Src/zsh.h`:
  https://github.com/zsh-users/zsh/blob/master/Src/zsh.h

## Licensing note

Before publishing the repository, add an explicit `LICENSE` file for this project.

The zsh source has its own permissive licence and copyright requirements. Because this implementation is informed by zsh's internal format and source-level behavior, review the upstream licence and preserve any required notices or attribution.

Do not assume that adding a generic open-source licence to this repository replaces obligations attached to upstream material.

## Responsible use

This tool is intended for:

- digital forensics;
- incident response;
- malware analysis;
- shell artifact research;
- defensive security;
- format research.

Analyze artifacts only where you are authorized to do so.

## Disclaimer

This is a forensic/research parser for an internal zsh representation.

It is not a replacement for zsh itself, and reconstructed output should not be assumed to be byte-for-byte equivalent to the original source.

Use the results as investigative evidence, validate important findings against additional artifacts, and treat all recovered code as untrusted.
