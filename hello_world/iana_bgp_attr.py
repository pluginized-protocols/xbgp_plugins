#!/usr/bin/env python3

import re
from sys import argv, exit


def get_iana_attrs(filename):
    attrs = list()

    with open(filename, 'r') as f:
        f.readline()  # skip csv header
        for line in f.readlines():
            line = line.strip().split(',')

            if not line[0].isdecimal():
                continue

            value = int(line[0])
            code = line[1].upper()
            code = re.sub(r"[^\w\s]", '', code)
            code = re.sub(r"\s+", '_', code)
            if re.search(r"DEPRECATED", code) is not None:
                continue

            attrs.append({'code': code, 'value': value})

        return attrs


def main(filename):
    attrs = get_iana_attrs(filename)

    header_str = ""
    known_attr_macro = "#define is_known_attr(code) ( \\\n"

    for attr in attrs:
        code, value = (attr['code'], attr['value'])
        print("#define %s_ATTR_ID %d" % (code, value))

        code_str = "%s_ATTR_ID" % code

        header_str += "#define %s %d\n" % (code_str, value)
        known_attr_macro += "    ((code) == %s) || \\\n" % code_str

    known_attr_macro += "false )"

    print(header_str)
    print("")
    print(known_attr_macro)


if __name__ == '__main__':
    if len(argv) != 2:
        print("Must take the IANA CSV path")
        exit(-1)

    main(argv[1])
