import csv

with open("data/Bot.csv", "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)

    print("HEADERS:")
    for h in reader.fieldnames:
        print(repr(h))

    row = next(reader)

    print("\nLABEL:")
    print(repr(row.get("Label")))

    print("\nPACKET COLUMNS:")
    for key in row.keys():
        if any(x in key.lower() for x in ["port", "fwd", "bwd", "label"]):
            print(repr(key))