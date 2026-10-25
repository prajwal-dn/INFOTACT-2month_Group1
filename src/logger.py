import csv, re, sys

def parse_candump_line(line):
    match = re.search(r'\(?(\d+\.\d+)\)?\s+\w+\s+([0-9A-Fa-f]+)\s+\[(\d+)\]\s+([0-9A-Fa-f\s]+)', line)
    if match:
        return {'timestamp': match.group(1), 'can_id': match.group(2), 'dlc': match.group(3), 'payload': match.group(4).strip()}
    return None

def process_file(input_path, output_path):
    parsed = 0
    with open(input_path, 'r') as infile, open(output_path, 'w', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=['timestamp', 'can_id', 'dlc', 'payload'])
        writer.writeheader()
        for line in infile:
            record = parse_candump_line(line)
            if record:
                writer.writerow(record)
                parsed += 1
    print(f'Processed {parsed} frames -> {output_path}')

if __name__ == '__main__':
    process_file(sys.argv[1], sys.argv[2])
