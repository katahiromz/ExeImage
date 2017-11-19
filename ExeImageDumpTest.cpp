// ExeImageDumpTest.cpp
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
    image.dump_dos(ss);
    image.dump_nt(ss);
    image.dump_import(ss);
    image.dump_export(ss);
    image.dump_delay_load(ss);
    puts(ss.str().c_str());

    return 0;
}

////////////////////////////////////////////////////////////////////////////
