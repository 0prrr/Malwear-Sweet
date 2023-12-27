# put this in project root
# -Wall would cause issue when compiling C program, adjust accordingly

def Settings(filename, **kwargs):
    flags = ['-x', 'c++', '-Wall', '-Wextra', '-Werror',
        '-I', '/usr/home/opr/Devil/lib/llvmingw281123-1706-bsd-x86_64/generic-w64-mingw32/include',
        '-I', '/usr/home/opr/Devil/lib/llvmingw281123-1706-bsd-x86_64/x86_64-w64-mingw32/include',
    ]

    debug = False

    return {"flags": flags, "do_cache": True}

Settings("")
