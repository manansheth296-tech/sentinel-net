import argparse
import pandas as pd


COLUMN_RENAME_MAP = {
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Fwd Packets Length Total",
    "TotLen Bwd Pkts": "Bwd Packets Length Total",

    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",

    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",

    "Pkt Len Min": "Packet Length Min",
    "Pkt Len Max": "Packet Length Max",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",

    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",

    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",

    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",

    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",

    "Init Fwd Win Byts": "Init Fwd Win Bytes",
    "Init Bwd Win Byts": "Init Bwd Win Bytes",
        "Flow Pkts/s": "Flow Packets/s",

    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",

    "Pkt Size Avg": "Avg Packet Size",

    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",

    "ECE Flag Cnt": "ECE Flag Count",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    print(f"[convert] Reading: {args.input}")

    df = pd.read_csv(args.input)

    before = len(df.columns)

    df = df.rename(columns=COLUMN_RENAME_MAP)

    after = len(df.columns)

    print(f"[convert] Columns: {before} -> {after}")

    # Check for duplicate column names after renaming
    duplicates = df.columns[df.columns.duplicated()].tolist()
    if duplicates:
        raise ValueError(
            f"Duplicate columns after V4 conversion: {duplicates}"
        )

    df.to_csv(args.output, index=False)

    print(f"[convert] Written: {args.output}")
    print(f"[convert] Rows: {len(df)}")
    print(f"[convert] Columns: {len(df.columns)}")


if __name__ == "__main__":
    main()