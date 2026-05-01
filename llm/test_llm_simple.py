import csv, sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from llm_decryption import LLMDecryption

correct_plaintext = correct_algorithm = correct_key = total = errors = 0
decryptor = LLMDecryption()

with open("/Users/cintaqia/Downloads/cipher_dataset.csv", "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    rows = list(reader)[:50] #I used the first 50 rows since it'll be very slow if I run it on all the 10k rows

for row in rows:
    try:
        pred_alg, pred_plain, pred_key = decryptor.decrypt(row["Output"])
    except Exception as e:
        print(f"Error: {e} | Row: {row}")
        errors += 1
        total += 1
        continue

    total += 1
    if pred_plain    == row["Input"]     : correct_plaintext += 1
    if pred_alg      == row["Algorithm"] : correct_algorithm += 1
    if pred_key      == int(row["Key"])  : correct_key       += 1

print(f"Samples: {total} | Errors: {errors}")
print(f"Plaintext accuracy:  {correct_plaintext / total:.2%}")
print(f"Algorithm accuracy:  {correct_algorithm / total:.2%}")
print(f"Key accuracy:        {correct_key / total:.2%}")
