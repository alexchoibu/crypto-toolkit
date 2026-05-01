import csv
import time
import os
import sys
import random
import matplotlib.pyplot as plt

# config

SAMPLE_SIZE = 50
RANDOM_SEED = 42
RUN_LLM = True
SHOW_DASHBOARD = True

DATASET_PATH = "./data/cipher_dataset.csv"
RESULTS_PATH = "./data/evaluation_results.csv"

# imports

sys.path.insert(0, os.path.abspath('.'))

from base_decryption.base_decryption import BaseDecryption

if RUN_LLM:
    try:
        from llm.llm_simple import LLMDecryption
    except ImportError:
        print("ERROR: Could not import LLMDecryption from llm_simple.py")
        print("Make sure llm_simple.py is in the same folder as evaluate.py")
        sys.exit(1)


# helper func

def pct(correct, total):
    """Return percentage as a formatted string."""
    if total == 0:
        return "N/A"
    return f"{correct / total:.1%}"


def pct_value(correct, total):
    """Return percentage as a numeric value for charts."""
    if total == 0:
        return 0
    return (correct / total) * 100


def safe_match_text(predicted, actual):
    """Compare plaintext while ignoring accidental leading/trailing spaces."""
    return predicted.strip() == actual.strip()


def show_dashboard(
    b_correct_alg,
    b_correct_plaintext,
    b_correct_key,
    b_errors,
    b_total_raw,
    b_avg_time,
    l_correct_alg,
    l_correct_plaintext,
    l_correct_key,
    l_errors,
    l_total_raw,
    l_avg_time,
    run_llm=True
):
    """Display a simple visual dashboard using matplotlib."""

    systems = ["Baseline"]
    alg_acc = [pct_value(b_correct_alg, b_total_raw)]
    plain_acc = [pct_value(b_correct_plaintext, b_total_raw)]
    key_acc = [pct_value(b_correct_key, b_total_raw)]
    error_rate = [pct_value(b_errors, b_total_raw)]
    avg_time = [b_avg_time]

    if run_llm:
        systems.append("LLM")
        alg_acc.append(pct_value(l_correct_alg, l_total_raw))
        plain_acc.append(pct_value(l_correct_plaintext, l_total_raw))
        key_acc.append(pct_value(l_correct_key, l_total_raw))
        error_rate.append(pct_value(l_errors, l_total_raw))
        avg_time.append(l_avg_time)

    # Figure 1: Accuracy metrics
    x = range(len(systems))
    width = 0.25

    plt.figure(figsize=(10, 6))
    plt.bar([i - width for i in x], alg_acc, width=width, label="Algorithm Accuracy")
    plt.bar(x, plain_acc, width=width, label="Plaintext Accuracy")
    plt.bar([i + width for i in x], key_acc, width=width, label="Key Accuracy")

    plt.xticks(x, systems)
    plt.ylim(0, 100)
    plt.ylabel("Accuracy (%)")
    plt.title("Crypto Toolkit Evaluation: Accuracy Comparison")
    plt.legend()
    plt.tight_layout()
    plt.show()

    # Figure 2: Runtime comparison
    plt.figure(figsize=(8, 5))
    plt.bar(systems, avg_time)
    plt.ylabel("Average Time Per Sample (seconds)")
    plt.title("Runtime Comparison")
    plt.tight_layout()
    plt.show()

    # Figure 3: Error rate comparison
    plt.figure(figsize=(8, 5))
    plt.bar(systems, error_rate)
    plt.ylim(0, 100)
    plt.ylabel("Error Rate (%)")
    plt.title("Error Rate Comparison")
    plt.tight_layout()
    plt.show()


# load data

print("=" * 70)
print("EC 521 Crypto Toolkit — Evaluation & Comparison")
print("=" * 70)

if not os.path.exists(DATASET_PATH):
    print(f"\nDataset not found at: {DATASET_PATH}")
    print("Generating a new dataset first...\n")
    from base_decryption.cipher_dataset_generator import create_cipher_dataset
    create_cipher_dataset()

with open(DATASET_PATH, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    all_rows = list(reader)

if not all_rows:
    print("ERROR: Dataset is empty.")
    sys.exit(1)

random.seed(RANDOM_SEED)

if SAMPLE_SIZE < len(all_rows):
    rows = random.sample(all_rows, SAMPLE_SIZE)
else:
    rows = all_rows

print(f"\nLoaded {len(rows)} samples from {DATASET_PATH}")
print(f"Random seed: {RANDOM_SEED}")
print(f"Running LLM evaluation: {RUN_LLM}\n")


# run baseline

print("-" * 70)
print("RUNNING BASELINE")
print("-" * 70)

baseline = BaseDecryption()

b_correct_alg = 0
b_correct_plaintext = 0
b_correct_key = 0
b_errors = 0
b_times = []

results = []

for i, row in enumerate(rows):
    true_alg = row["Algorithm"].strip()
    true_plaintext = row["Input"].strip()
    ciphertext = row["Output"].strip()
    true_key = int(row["Key"].strip())

    start = time.time()

    try:
        pred_alg, pred_plaintext, pred_key = baseline.decrypt(ciphertext)
        elapsed = time.time() - start
        b_times.append(elapsed)

        alg_correct = pred_alg.lower() == true_alg.lower()
        plain_correct = safe_match_text(pred_plaintext, true_plaintext)
        key_correct = pred_key == true_key

        if alg_correct:
            b_correct_alg += 1
        if plain_correct:
            b_correct_plaintext += 1
        if key_correct:
            b_correct_key += 1

        results.append({
            "sample_index": i + 1,
            "true_algorithm": true_alg,
            "true_key": true_key,
            "ciphertext": ciphertext[:60] + "..." if len(ciphertext) > 60 else ciphertext,
            "baseline_alg": pred_alg,
            "baseline_alg_correct": alg_correct,
            "baseline_key": pred_key,
            "baseline_key_correct": key_correct,
            "baseline_plain_correct": plain_correct,
            "baseline_time_sec": round(elapsed, 4),
            "llm_alg": "N/A",
            "llm_alg_correct": "N/A",
            "llm_key": "N/A",
            "llm_key_correct": "N/A",
            "llm_plain_correct": "N/A",
            "llm_time_sec": "N/A",
        })

    except Exception as e:
        elapsed = time.time() - start
        b_errors += 1

        print(f"Baseline error on row {i + 1}: {e}")

        results.append({
            "sample_index": i + 1,
            "true_algorithm": true_alg,
            "true_key": true_key,
            "ciphertext": ciphertext[:60] + "..." if len(ciphertext) > 60 else ciphertext,
            "baseline_alg": "ERROR",
            "baseline_alg_correct": False,
            "baseline_key": "ERROR",
            "baseline_key_correct": False,
            "baseline_plain_correct": False,
            "baseline_time_sec": round(elapsed, 4),
            "llm_alg": "N/A",
            "llm_alg_correct": "N/A",
            "llm_key": "N/A",
            "llm_key_correct": "N/A",
            "llm_plain_correct": "N/A",
            "llm_time_sec": "N/A",
        })

    if (i + 1) % 10 == 0:
        print(f"Baseline progress: {i + 1}/{len(rows)} complete")

b_total_valid = len(rows) - b_errors
b_total_raw = len(rows)
b_avg_time = sum(b_times) / len(b_times) if b_times else 0

print(f"\nBaseline complete. Errors: {b_errors}")


# run llm

l_correct_alg = 0
l_correct_plaintext = 0
l_correct_key = 0
l_errors = 0
l_times = []

if RUN_LLM:
    print("\n" + "-" * 70)
    print("RUNNING LLM")
    print("-" * 70)

    llm = LLMDecryption()

    for i, row in enumerate(rows):
        true_alg = row["Algorithm"].strip()
        true_plaintext = row["Input"].strip()
        ciphertext = row["Output"].strip()
        true_key = int(row["Key"].strip())

        start = time.time()

        try:
            pred_alg, pred_plaintext, pred_key = llm.decrypt(ciphertext)
            elapsed = time.time() - start
            l_times.append(elapsed)

            alg_correct = pred_alg.lower() == true_alg.lower()
            plain_correct = safe_match_text(pred_plaintext, true_plaintext)
            key_correct = pred_key == true_key

            if alg_correct:
                l_correct_alg += 1
            if plain_correct:
                l_correct_plaintext += 1
            if key_correct:
                l_correct_key += 1

            results[i]["llm_alg"] = pred_alg
            results[i]["llm_alg_correct"] = alg_correct
            results[i]["llm_key"] = pred_key
            results[i]["llm_key_correct"] = key_correct
            results[i]["llm_plain_correct"] = plain_correct
            results[i]["llm_time_sec"] = round(elapsed, 4)

            print(
                f"[{i + 1}/{len(rows)}] "
                f"True: {true_alg:<16} | "
                f"Baseline: {results[i]['baseline_alg']:<16} | "
                f"LLM: {pred_alg:<16} | "
                f"{elapsed:.2f}s"
            )

        except Exception as e:
            elapsed = time.time() - start
            l_errors += 1

            results[i]["llm_alg"] = "ERROR"
            results[i]["llm_alg_correct"] = False
            results[i]["llm_key"] = "ERROR"
            results[i]["llm_key_correct"] = False
            results[i]["llm_plain_correct"] = False
            results[i]["llm_time_sec"] = round(elapsed, 4)

            print(f"LLM error on row {i + 1}: {e}")

    l_total_valid = len(rows) - l_errors
    l_total_raw = len(rows)
    l_avg_time = sum(l_times) / len(l_times) if l_times else 0

    print(f"\nLLM complete. Errors: {l_errors}")

else:
    l_total_valid = 0
    l_total_raw = len(rows)
    l_avg_time = 0


# print results

print("\n")
print("=" * 70)
print("FINAL RESULTS COMPARISON")
print("=" * 70)

header = f"{'Metric':<32} {'Baseline':>14} {'LLM':>14}"
print(header)
print("-" * 70)

print(f"{'Samples tested':<32} {b_total_raw:>14} {l_total_raw if RUN_LLM else 'N/A':>14}")
print(f"{'Errors':<32} {b_errors:>14} {l_errors if RUN_LLM else 'N/A':>14}")
print(f"{'Algorithm accuracy':<32} {pct(b_correct_alg, b_total_valid):>14} {pct(l_correct_alg, l_total_valid) if RUN_LLM else 'N/A':>14}")
print(f"{'Plaintext accuracy':<32} {pct(b_correct_plaintext, b_total_valid):>14} {pct(l_correct_plaintext, l_total_valid) if RUN_LLM else 'N/A':>14}")
print(f"{'Key accuracy':<32} {pct(b_correct_key, b_total_valid):>14} {pct(l_correct_key, l_total_valid) if RUN_LLM else 'N/A':>14}")
print(f"{'Avg time per sample':<32} {str(round(b_avg_time, 4)) + 's':>14} {(str(round(l_avg_time, 4)) + 's') if RUN_LLM else 'N/A':>14}")

print("=" * 70)


# per cipher breakdown

print("\nPER-ALGORITHM BREAKDOWN")

for alg in ["caesar", "single_byte_xor"]:
    alg_rows = [r for r in results if r["true_algorithm"] == alg]

    if not alg_rows:
        continue

    b_alg_correct = sum(1 for r in alg_rows if r["baseline_alg_correct"] is True)
    b_plain_correct = sum(1 for r in alg_rows if r["baseline_plain_correct"] is True)
    b_key_correct = sum(1 for r in alg_rows if r["baseline_key_correct"] is True)

    print(f"\n{alg.upper()} ({len(alg_rows)} samples)")
    print(f"  Baseline algorithm accuracy : {pct(b_alg_correct, len(alg_rows))}")
    print(f"  Baseline plaintext accuracy : {pct(b_plain_correct, len(alg_rows))}")
    print(f"  Baseline key accuracy       : {pct(b_key_correct, len(alg_rows))}")

    if RUN_LLM:
        l_alg_correct = sum(1 for r in alg_rows if r["llm_alg_correct"] is True)
        l_plain_correct = sum(1 for r in alg_rows if r["llm_plain_correct"] is True)
        l_key_correct = sum(1 for r in alg_rows if r["llm_key_correct"] is True)

        print(f"  LLM algorithm accuracy      : {pct(l_alg_correct, len(alg_rows))}")
        print(f"  LLM plaintext accuracy      : {pct(l_plain_correct, len(alg_rows))}")
        print(f"  LLM key accuracy            : {pct(l_key_correct, len(alg_rows))}")


# save results to csv

os.makedirs("./data", exist_ok=True)

if results:
    with open(RESULTS_PATH, "w", newline="", encoding="utf-8") as f:
        fieldnames = results[0].keys()
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nDetailed results saved to: {RESULTS_PATH}")


# dashboard

if SHOW_DASHBOARD:
    show_dashboard(
        b_correct_alg=b_correct_alg,
        b_correct_plaintext=b_correct_plaintext,
        b_correct_key=b_correct_key,
        b_errors=b_errors,
        b_total_raw=b_total_raw,
        b_avg_time=b_avg_time,
        l_correct_alg=l_correct_alg,
        l_correct_plaintext=l_correct_plaintext,
        l_correct_key=l_correct_key,
        l_errors=l_errors,
        l_total_raw=l_total_raw,
        l_avg_time=l_avg_time,
        run_llm=RUN_LLM
    )