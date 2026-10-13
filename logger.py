import csv
import sys
import os

def parse_candump_line(line):
    try:
        line = line.strip()
        if not line:
            return None
        parts = line.split()

        if "#" in line:
            for part in parts:
                if "#" in part:
                    can_id, payload = part.split("#")
                    return {
                        "timestamp": parts[0].strip("()") if parts[0].startswith("(") else "",
                        "can_id": can_id,
                        "payload": payload,
                        "dlc": len(payload) // 2
                    }

        if len(parts) >= 4:
            can_id = parts[1]
            dlc = 0
            for p in parts:
                if p.startswith("[") and p.endswith("]"):
                    dlc = int(p.strip("[]"))
                    break
            payload_parts = []
            found_dlc = False
            for p in parts:
                if found_dlc:
                    payload_parts.append(p)
                if p.startswith("[") and p.endswith("]"):
                    found_dlc = True
            payload = "".join(payload_parts)
            return {
                "timestamp": "",
                "can_id": can_id,
                "payload": payload,
                "dlc": dlc
            }
        return None
    except Exception:
        return None

def save_to_csv(data, filename="can_log.csv"):
    file_exists = os.path.isfile(filename)
    with open(filename, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "can_id", "payload", "dlc"])
        if not file_exists or os.path.getsize(filename) == 0:
            writer.writeheader()
        writer.writerow(data)

def process_file(input_file, output_file="can_log.csv"):
    if not os.path.isfile(input_file):
        print(f"Error: {input_file} not found")
        return
    count = 0
    with open(input_file, "r") as f:
        for line in f:
            parsed = parse_candump_line(line)
            if parsed:
                save_to_csv(parsed, output_file)
                count += 1
    print(f"Processed {count} frames -> {output_file}")

if __name__ == "__main__":
    input_file = sys.argv[1] if len(sys.argv) > 1 else "candump_output.txt"
    process_file(input_file)
