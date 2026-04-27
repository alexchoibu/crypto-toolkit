# crypto-toolkit

Automating the identification of cryptographic artifacts can improve efficiency and reduce reliance on manual analysis. This project proposes the development of an automated toolkit capable of identifying common cryptographic artifacts, including classical ciphers, XOR-based encryption, encoding schemes, and hash outputs, while performing automated cryptanalysis where feasible. The project will also evaluate whether LLM-assisted analysis can improve performance compared to traditional heuristic and statistical approaches.

```
crypto-toolkit-main/
│
├── README.md
├── .gitignore
├── evaluation.py                    ← Evaluation & comparison script
├── test_baseline.py                 ← Baseline test script
│
├── base_decryption/
│   ├── __init__.py
│   ├── base_decryption.py           ← Main decryption class (Caesar + XOR)
│   ├── cipher_dataset_generator.py  ← Dataset generator (change INPUT_FILE to swap datasets)
│   ├── sentences.txt                ← Simple English sentences (Kaggle)
│   ├── harder_sentences.txt         ← High-quality sentences with proper nouns (HuggingFace)
│   ├── wordlist.txt                 ← ~300k English words for scoring
│   └── 1-1000.txt                   ← Top 1000 common words (weighted higher)
│
├── data/
|   |── 0_9999_hashes.csv                   ← Generated umber list hash data
|   |── 4-digits-0000-9999.txt              ← Number list containing strings 0000 to 9999
│   |── cipher_dataset.csv                  ← Generated dataset (10k Caesar + XOR samples)
|   |── create_data.py                      ← Dataset generation/accumulation script
|   |── cryptography_dataset_enhanced.csv   ← First complex algorithm dataset from Kaggle
|   |── cryptography_dataset_processed.csv  ← Second complex algorithm dataset from Kaggle
|   |── data.csv                            ← Organized encoded dataset
|   |── data.jsonl                          ← Encoded artifacts dataset from Hugging Face
│   |── dataset.csv                         ← Complex algorithm dataset (AES, RSA, etc.)
|   |── hashgen.py                          ← Hash generation script from SecLists
│   ├── evaluation_results.csv              ← Output: row-by-row results from evaluation.py
│   └── evaluation_chart.png                ← Output: visual comparison chart
│
└── llm/
    ├── __init__.py
    ├── llm_simple.py                ← LLM decryption for Caesar + XOR (Llama3.2)
    ├── llm_complex.py               ← LLM identifier for 20+ algorithm types
    ├── test_llm_simple.py           ← Test script for llm_simple
    └── test_llm_complex.py          ← Test script for llm_complex
