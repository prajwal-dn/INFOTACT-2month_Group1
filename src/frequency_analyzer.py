import csv, sys
from collections import Counter

def analyze(filepath):
    with open(filepath, 'r') as f:
        ids = [row['can_id'] for row in csv.DictReader(f)]
    counts = Counter(ids)
    total = sum(counts.values())
    for cid, count in counts.most_common():
        print(f'ID: 0x{cid} | Count: {count} | {count/total*100:.1f}%')

if __name__ == '__main__':
    analyze(sys.argv[1])
