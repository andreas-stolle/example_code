#include "Cell.h"

Cell::Cell()
{
    bottomWall = true;
    rightWall = true;
    topWall = true;
    leftWall = true;
    unvisited = true;
}

bool Cell::isUnvisited()
{
    return unvisited;
}

void Cell::setVisit()
{
    unvisited = false;
}

void Cell::setUnvisited()
{
    unvisited = true;
}

bool Cell::isWall(int wall)
{
    switch (wall)
    {
        case 0: return topWall;
        case 1: return rightWall;
        case 2: return bottomWall;
        case 3: return leftWall;
    }
}

void Cell::removeWall(int wall)
{
    switch (wall)
    {
        case 0: topWall = false; break;
        case 1: rightWall = false; break;
        case 2: bottomWall = false; break;
        case 3: leftWall = false; break;
    }
}

void Cell::setCoordinates(int xNew, int yNew)
{
    x = xNew;
    y = yNew;
}

int Cell::getX()
{
    return x;
}

int Cell::getY()
{
    return y;
}
