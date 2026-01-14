# File Diff Tool (x86 Assembly)

Implements a simplified `diff`-style file comparison tool using the Longest Common Subsequence algorithm. The core comparison logic is written in x86 assembly, with a small C framework used for I/O and program setup.

The project focuses on low-level file handling, manual memory management, and implementing a non-trivial algorithm without relying on standard library abstractions.

## Build

macOS / Linux (requires `gcc` and an x86 toolchain):

```bash
gcc -O2 -Wall -Wextra a5-diff-frame.c a5-diff.S -o diff
```

## Run

```bash
./diff <file1> <file2>
```

Example:

```bash
./diff file1.txt file2.txt
```