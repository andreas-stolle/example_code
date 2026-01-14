#ifndef MAZE_CELL_H
#define MAZE_CELL_H

class Cell
{
    public:
        Cell();
        bool isWall(int wall);
        void removeWall(int wall);
        bool isUnvisited();
        void setVisit();
        void setUnvisited();
        void setCoordinates(int x, int y);
        int getX();
        int getY();

    private:
        bool bottomWall, rightWall, topWall, leftWall, unvisited;
        int x, y;
};

#endif
