// ExeImageDumpTest.cpp --- Test for ExeImage
////////////////////////////////////////////////////////////////////////////

#define _CRT_SECURE_NO_WARNINGS
#include "ExeImage.hpp"

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        puts("Usage: ExeImageDumpTest exe_file.exe\n");
        return -1;
    }

    codereverse::ExeImage image;

    if (!image.load(argv[1]))
    {
        fprintf(stderr, "failed to load\n");
        return -1;
    }

    std::stringstream ss;
    image.dump_all(ss);
    puts(ss.str().c_str());

    return 0;
}

////////////////////////////////////////////////////////////////////////////
