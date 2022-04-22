import json
import statistics
import sys

from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

__EXTENSION = "*.monitor.json"


def process_json(file: 'Path'):
    print(f"Processing {str(file)}.")
    with open(str(file), 'r') as f:
        samples = json.load(f)

    max_uss = -1

    for sample in samples:
        max_uss = max(max_uss, sample['effective_mem'][-3])

    return max_uss


def name_on_first_delim(name: str, delim: str = '.'):
    idx_delim = name.index(delim)
    return name[:idx_delim]


def add_stats(mem_exps: dict[str, Any]):
    for name, exp in mem_exps.items():
        lst_mem = exp['max_mem']
        mem_exps[name] = dict(
            exp,
            median=statistics.median(lst_mem),
            mean=statistics.mean(lst_mem),
            max=max(lst_mem),
            min=min(lst_mem)
        )


def main(path_dir: 'Path'):
    files = path_dir.glob(__EXTENSION)

    max_mem = dict()

    for file in files:
        exp_name = name_on_first_delim(file.name)
        mem = process_json(file)

        if exp_name not in max_mem:
            max_mem[exp_name] = {
                'max_mem': list()
            }

        max_mem[exp_name]['max_mem'].append(mem)

    add_stats(max_mem)

    with open('memory_consumption.json', 'w') as f:
        json.dump(max_mem, f)


def get_mem(file: 'Path'):
    with open(str(file), 'r') as f:
        samples = json.load(f)

    return [x['effective_mem'][-3] for x in samples]


def main2(files: list['Path']):
    for file in files:
        mem = get_mem(file)
        plt.plot(mem, label=file.name)

    plt.grid()
    plt.legend()
    plt.show()


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        raise ValueError("Must take one argument")

    path_files = []

    for str_file in sys.argv[1:]:
        path_files.append(Path(str_file))

    main2(path_files)

    # directory = Path(sys.argv[1])
    # main(directory)
