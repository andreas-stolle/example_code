#include <iostream>
#include "Maze.h"
#include <cstdlib>
#include <time.h>

int main(int argc, char* argv[])
{
    try
    {
        int rows = std::stoi (argv[1]);
        int columns = std::stoi (argv[2]);
        int seed;

        if (argc == 4)
            seed = std::stoi(argv[3]);
        else
            seed = time(0);

        if (argc == 3 || argc == 4)
        {
            srand(seed);
            Maze maze(rows, columns);
            maze.generateMaze(0, 0);
            maze.reset();
            maze.findPath(0,0,rows - 1,columns - 1);
            maze.printMaze();
        }
        else
            throw std::runtime_error("invalid parameters");
    }
    catch(std::runtime_error& excpt)
    {
        std::cout << excpt.what() << std::endl;
        return 1;
    }

    return 0;
}
