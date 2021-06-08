#!/usr/bin/env python3

import json
import sys
import subprocess
import shlex


def do_make(programs):
    cmdline = 'make THE_MAIN={main} THE_FILES="{srcs}"'
    nb_programs = len(programs)

    for i, program in zip(range(1, nb_programs + 1), programs):
        main = program['main']
        srcs = ' '.join(program['src'])
        cmd = shlex.split(cmdline.format(main=main,
                                         srcs=srcs))

        print("(%d/%d) Compiling %s" % (i, nb_programs, main), end='\r')

        cp = subprocess.run(cmd,
                            shell=False,
                            capture_output=True)
        # exits if compilation fails
        try:
            cp.check_returncode()
        except subprocess.CalledProcessError as e:
            print('\n"%s" returned an non zero exit code: %d' % (' '.join(cmd), e.returncode))
            print("stdout: %s\nstderr: %s" % (e.stdout.decode(),
                                              e.stderr.decode()))
            exit(1)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Should take the json path to the files to compile (check cbmc_compile.json)")
        exit(0)

    with open(sys.argv[1], 'r') as f:
        _programs = json.load(f)

    do_make(_programs)
