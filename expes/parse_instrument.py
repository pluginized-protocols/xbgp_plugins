import csv
import statistics
import sys


def read_csv(str_file: str):
    parsed_csv = {}
    with open(str_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            fn_name = row['instrument_name']
            if fn_name not in parsed_csv:
                parsed_csv[fn_name] = {
                    'sample_time': [],
                    'counter': row['counter']
                }

            sec = int(row['secs'])
            nanosecs = int(row['nanosecs'])

            tot_time = (sec * (10 ** 9)) + nanosecs
            parsed_csv[fn_name]['sample_time'].append(tot_time)
    return parsed_csv


def main(str_file: str):
    exps = read_csv(str_file)

    print("instrument,median_time,nb_call")
    for exp_name, x in exps.items():
        median = statistics.median_low(x['sample_time'])
        print(f"{exp_name},{median},{x['counter']}")


if __name__ == '__main__':
    main(sys.argv[1])
