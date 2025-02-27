# Fast-Bitcoin-Wallet-generator-checker
Generates random legacy addresses, check if it match a predefined addresses list (filtered_addresses.tsv)
If there is a match, it output to match.txt (PubAddress, WIF, PrivateKey)


This project implements a high-performance Bitcoin key generation scanner using a fixed-size ring buffer with `mmap` for continuous, efficient I/O. 
The ring buffer avoids file deletion overhead by continuously overwriting old entries, allowing the process to run seamlessly.

## Features

- **Fixed-Size Ring Buffer:**  
  Uses `mmap` to maintain a continuous file (`result.txt`) of a fixed size. When the end is reached, it wraps around to overwrite older entries.

- **Multiprocessing:**  
  Utilizes multiple worker processes (configurable via `NUM_WORKERS`) for Bitcoin key generation.

- **Startup Matching Check:**  
  On startup, if `result.txt` exists, a quick matching check is performed against addresses in a TSV file (`filtered_addresses.tsv`).

## Requirements

- Python 3.x
- filtered_addresses.tsv where you have bitcoin addresses you search
- [Colorama](https://pypi.org/project/colorama/)  
  Install via:
  ```sh
  pip install colorama
