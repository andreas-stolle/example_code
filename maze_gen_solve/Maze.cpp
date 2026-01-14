#include <vector>
#include <iostream>
#include <cstdlib>
#include "Cell.h"
#include "Maze.h"

Maze::Maze(int newRows, int newColumns)
{
    rows = newRows;
    columns = newColumns;
    std::vector<std::vector<Cell>> newField(rows);
    field=newField;

    for (int x = 0; x < rows; x++)
    {
        std::vector<Cell> newRow(columns);
        field.at(x) = newRow;
    }
}

void Maze::generateMaze(int x, int y)
{
    field.at(x).at(y).setVisit();
    std::vector<int> order = generateRandom();
    for (int i = 0; i < order.size(); i++)
        goDirection(x, y, order.at(i));
}

void Maze::goDirection(int x, int y,int direction)
{
    switch (direction)
    {
        case 0:
            if(x > 0 && field.at(x - 1).at(y).isUnvisited() && field.at(x).at(y).isWall(0))
            {
                field.at(x).at(y).removeWall(0);
                field.at(x - 1).at(y).removeWall(2);
                Maze::generateMaze(x - 1, y);
            } break;
        case 1:
            if (y < field.at(0).size() - 1 && field.at(x).at(y + 1).isUnvisited() && field.at(x).at(y).isWall(1))
            {
                field.at(x).at(y).removeWall(1);
                field.at(x).at(y + 1).removeWall(3);
                Maze::generateMaze(x, y + 1);
            } break;
        case 2:
            if (x < field.size() - 1 && field.at(x + 1).at(y).isUnvisited() && field.at(x).at(y).isWall(2))
            {
                field.at(x).at(y).removeWall(2);
                field.at(x + 1).at(y).removeWall(0);
                Maze::generateMaze(x + 1, y);
            } break;
        case 3:
            if (y > 0 && field.at(x).at(y - 1).isUnvisited() && field.at(x).at(y).isWall(3))
            {
                field.at(x).at(y).removeWall(3);
                field.at(x).at(y - 1).removeWall(1);
                Maze::generateMaze(x, y - 1);
            } break;
    }
}

bool Maze::findPath(int xStart, int yStart, int xEnd, int yEnd)
{
    std::vector<Cell> neighbours;
    field.at(xStart).at(yStart).setVisit();
    setCoordinates();

    if (xStart == xEnd && yStart == yEnd)
        return true;

    findNeighbours(neighbours, xStart, yStart);
    for (int i = 0; i < neighbours.size(); i++)
    {
        if (neighbours.at(i).isUnvisited() &&
            findPath(neighbours.at(i).getX(), neighbours.at(i).getY(), xEnd, yEnd))
                return true;
    }
    field.at(xStart).at(yStart).setUnvisited();
    return false;
}

void Maze::findNeighbours(std::vector<Cell>& neighbours, int x, int y)
{
    if (!field.at(x).at(y).isWall(0))
        neighbours.push_back(field.at(x - 1).at(y));
    if (!field.at(x).at(y).isWall(1))
        neighbours.push_back(field.at(x).at(y + 1));
    if (!field.at(x).at(y).isWall(2))
        neighbours.push_back(field.at(x + 1).at(y));
    if (!field.at(x).at(y).isWall(3))
        neighbours.push_back(field.at(x).at(y - 1));
}

void Maze::setCoordinates()
{
    for (int x = 0; x < rows; x++)
    {
        for (int y = 0; y < columns; y++)
            field.at(x).at(y).setCoordinates(x, y);
    }
}

void Maze::reset()
{
    for (int x = 0; x < rows; x++)
    {
        for (int y = 0; y < columns; y++)
            field.at(x).at(y).setUnvisited();
    }
}

void Maze::printMaze()
{
    std::cout << "+";
    for (int y = 0; y < columns; y++)
        std::cout << "---+";
    std::cout << std::endl;
    for (int x = 0; x < rows; x++)
    {
        std::cout << "|";
        for (int y = 0; y < columns; y++)
        {
            std::cout << " ";
            if (field.at(x).at(y).isUnvisited())
                std::cout << " ";
            else
                std::cout << ".";
            std::cout << " ";

            if (field.at(x).at(y).isWall(1))
                std::cout << "|";
            else
                std::cout << " ";
        }
        std::cout << std::endl << "+";
        for (int y = 0; y < columns; y++)
        {
            if(field.at(x).at(y).isWall(2))
                std::cout << "---+";
            else
                std::cout << "   +";
        }
        std::cout << std::endl;
    }
}

std::vector<int> Maze::generateRandom()
{
    std::vector<std::vector<int>> order{{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2},
                                        {0, 3, 2, 1}, {1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0},
                                        {1, 3, 0, 2}, {1, 3, 2, 0}, {2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3},
                                        {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0}, {3, 0, 1, 2}, {3, 0, 2, 1},
                                        {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0}};
    return order.at(rand()%24);
}
