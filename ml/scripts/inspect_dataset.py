import pandas as pd

DATASET_PATH = "ml/data/enron_spam_data.csv"

df = pd.read_csv(DATASET_PATH)

print("\nFIRST 5 ROWS:")
print(df.head())

print("\nCOLUMNS:")
print(df.columns.tolist())

print("\nDATASET SHAPE:")
print(df.shape)

print("\nMISSING VALUES:")
print(df.isnull().sum())

print("\nLABEL COUNTS:")
print(df["Spam/Ham"].value_counts())

print("\nLABEL PERCENTAGES:")
print(df["Spam/Ham"].value_counts(normalize=True) * 100)