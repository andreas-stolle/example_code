# IJVM Bytecode Interpreter (C)

A small IJVM virtual machine interpreter written in C. It loads and executes compiled IJVM bytecode binaries using a stack-based execution model (program counter, operand stack, and constant pool).

The interpreter executes raw IJVM bytecode and does **not** parse IJVM assembly (`.jas`) source files.

## Build

macOS / Linux:

```bash
gcc -O2 -Wall -Wextra main.c ijvm.c util.c -o ijvm
```

## Run

Run an IJVM bytecode binary:

```bash
./ijvm program.bin
```

### Minimal example

Create a small IJVM binary that prints `Hi`:

```bash
echo "1deadfad0000000000000000000000000a0000001048fd1069fd100afdff" | xxd -r -p > hi.bin
```

Execute it:

```bash
./ijvm hi.bin
```

Expected output:

```
Hi
```