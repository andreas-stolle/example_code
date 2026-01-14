# Maze Generator + Solver (C++)

Generates a random maze using depth-first search (recursive backtracking) and then solves it by finding a path from the top-left cell to the bottom-right cell. The maze and the solution path are printed to standard output.

## Build

macOS / Linux:

```bash
g++ -std=c++17 -O2 -Wall -Wextra main.cpp Maze.cpp Cell.cpp -o maze
```

(Use `clang++` instead of `g++` if needed.)

## Run

```bash
./maze <rows> <cols> [seed]
```

Example:

```bash
./maze 10 10 5
```