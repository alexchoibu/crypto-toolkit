from base_decryption.base_decryption import BaseDecryption
import csv

from base_decryption.cipher_dataset_generator import create_cipher_dataset

correct_plaintext = 0
correct_algorithm = 0
correct_key = 0
total = 0

decryptor = BaseDecryption()

create_cipher_dataset()

with open("./data/cipher_dataset.csv", "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    for row in reader:
        true_algorithm = row["Algorithm"]
        true_plaintext = row["Input"]
        ciphertext = row["Output"]
        true_key = int(row["Key"])

        pred_algorithm, pred_plaintext, pred_key = decryptor.decrypt(
            ciphertext
        )

        total += 1

        if pred_plaintext == true_plaintext:
            correct_plaintext += 1

        if pred_algorithm == true_algorithm:
            correct_algorithm += 1

        if pred_key == true_key:
            correct_key += 1

        if pred_plaintext != true_plaintext:
            print("----")
            print("row:", row)
            print("Predicted:", pred_algorithm, pred_key)

print(f"Total samples: {total}")
print(f"Plaintext accuracy: {correct_plaintext / total:.2%}")
print(f"Algorithm accuracy: {correct_algorithm / total:.2%}")
print(f"Key accuracy: {correct_key / total:.2%}")
