import re
import pandas as pd
import numpy as np

# Open datasets
df_encode = pd.read_csv('data.csv', delimiter=',')
df_crypto = pd.read_csv('cryptography_dataset_enhanced.csv', delimiter=',')
df_crypto2 = pd.read_csv('cryptography_dataset_processed.csv', delimiter=',')
df_hash = pd.read_csv('0_9999_hashes.csv', delimiter=',')

# Clean up encoding instructions
df_encode.loc[df_encode['instruction'].str.contains('hex', case=False), 'instruction'] = "Base64 to HEX"
df_encode.loc[df_encode['instruction'].str.contains('json', case=False), 'instruction'] = "Base64 to JSON"

# Clean up cryptographic keys with newlines
pattern = r'-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----'

extracted_crypto = df_crypto["Key"].str.extract(pattern, flags=re.DOTALL, expand=False)
cleaned_crypto = extracted_crypto.str.replace(r'[\r\n]+', '', regex=True).str.strip()
df_crypto["Key"] = cleaned_crypto.where(cleaned_crypto.notna(), df_crypto["Key"])

extracted_crypto2 = df_crypto2["Key"].str.extract(pattern, flags=re.DOTALL, expand=False)
cleaned_crypto2 = extracted_crypto2.str.replace(r'[\r\n]+', '', regex=True).str.strip()
df_crypto2["Key"] = cleaned_crypto2.where(cleaned_crypto2.notna(), df_crypto2["Key"])

# Rename second cryptography dataset Triple DES to 3DES
df_crypto2.loc[df_crypto2['Algorithm'].str.contains('Triple DES', case=False), 'Algorithm'] = "3DES"

# Rename columns
df_encode = df_encode.rename(columns={"instruction": "Algorithm", "input": "Input", "output": "Output"})
df_crypto = df_crypto.rename(columns={"Plaintext": "Input", "Ciphertext": "Output"})
df_crypto2 = df_crypto2.rename(columns={"Ciphertext": "Output"})

# Remove unnecessary columns from second cryptography dataset
df_crypto2 = df_crypto2.drop(columns=['Key Length (bits)', 'Ciphertext Length (bytes)'])

# Add Key column to encode dataset
df_encode['Key'] = np.nan

# Add Input column to second cryptography dataset
df_crypto2['Input'] = np.nan

# Reorder columns in cryptography datasets
df_crypto = df_crypto[["Algorithm", "Input", "Output", "Key"]]
df_crypto2 = df_crypto2[["Algorithm", "Input", "Output", "Key"]]

# Combine datasets
df = pd.concat([df_encode, df_crypto], ignore_index=True)
df = pd.concat([df, df_crypto2], ignore_index=True)
df = pd.concat([df, df_hash], ignore_index=True)

# Shuffle dataset
df = df.sample(frac=1).reset_index(drop=True)

# Save combined dataset
df.to_csv('dataset.csv', index=False)

print(df['Algorithm'].value_counts())