#ifndef MAZE_MAZE_H
#define MAZE_MAZE_H
#include <vector>
#include "Cell.h"

class Maze
{
    public:
        Maze(int rows, int columns);
        void generateMaze(int y, int x);
        void printMaze();
        std::vector<int> generateRandom();
        void goDirection(int x, int y, int direction);
        void reset();
        bool findPath(int xStart, int yStart, int xEnd, int yEnd);
        void setCoordinates();
        void findNeighbours(std::vector<Cell>& neighbours, int x, int y);

    private:
        int rows, columns;
        std::vector<std::vector<Cell>> field;
};

#endif
