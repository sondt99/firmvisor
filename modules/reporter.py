import json

def save_report(report, output):
    with open(output, 'w') as f:
        json.dump(report, f, indent=4)
