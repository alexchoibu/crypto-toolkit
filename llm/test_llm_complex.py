import csv
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from llm_identifier import LLMIdentifier

DATASET_PATH = "/Users/cintaqia/Downloads/dataset.csv"
SAMPLE_SIZE  = 50 #Did pilot evaluation only on the first 50 rows

identifier = LLMIdentifier(model="llama3") #feel free to change it to other Llama versions if you want. Llama 4 is just huge that's why I used Llama3

with open(DATASET_PATH, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    all_rows = [row for row in reader if row["Algorithm"].strip() != "Algorithm"]

rows = all_rows[:SAMPLE_SIZE]

correct_constrained        = 0
correct_constrained_w_key  = 0
correct_unconstrained      = 0
total  = 0
errors = 0

print(f"{'True':<20} | {'Constrained':<20} | {'Constrained+Key':<20} | {'Unconstrained':<20}")
print("-" * 90)

for row in rows:
    true_alg   = row["Algorithm"].strip()
    ciphertext = row["Output"].strip()
    key        = row["Key"].strip()

    try:
        result_constrained       = identifier.identify_constrained(ciphertext)
        result_constrained_w_key = identifier.identify_constrained_with_key(ciphertext, key) if key else result_constrained
        result_unconstrained     = identifier.identify_unconstrained(ciphertext)
    except Exception as e:
        print(f"Error on row (Algorithm={true_alg}): {e}")
        errors += 1
        total  += 1
        continue

    total += 1

    pred_constrained       = result_constrained["algorithm"].strip()
    pred_constrained_w_key = result_constrained_w_key["algorithm"].strip()
    pred_unconstrained     = result_unconstrained["algorithm"].strip()

    if pred_constrained.lower()       == true_alg.lower(): correct_constrained       += 1
    if pred_constrained_w_key.lower() == true_alg.lower(): correct_constrained_w_key += 1
    if pred_unconstrained.lower()     == true_alg.lower(): correct_unconstrained      += 1

    print(f"{true_alg:<20} | {pred_constrained:<20} | {pred_constrained_w_key:<20} | {pred_unconstrained:<20}")

#Results Table

print("\n" + "=" * 90)
print(f"Total samples : {total}")
print(f"Errors        : {errors}")
print(f"")
print(f"Accuracy - Constrained (no key) : {correct_constrained       / total:.2%}")
print(f"Accuracy - Constrained (w/ key) : {correct_constrained_w_key / total:.2%}")
print(f"Accuracy - Unconstrained        : {correct_unconstrained      / total:.2%}")
