# Mimicry Provenance Generator

A mimicry attack research tool for provenance-based intrusion detection systems (IDS). It generates **evasion graphs** — provenance graphs where real attack paths are injected into benign system activity in a way that tries to evade detection by graph-based anomaly detectors.

The core idea: take a benign provenance graph (system call traces), insert an attack path into it, and add benign substructures to camouflage the attack — creating a "mimicry" evasion graph.

## Repo Structure

| Directory/File | Purpose |
|---|---|
| `insertAttackPath.py` | **Core generator** — injects attack paths into benign provenance graphs |
| `parser/` | Parsers to convert raw data into the required CSV formats (`ssParser.py`, `tcParser.py`, etc.) |
| `provDetector/` | Implementation of the **ProvDetector** anomaly detection system (path-based) |
| `FGA/` | Implementation of **FGA** (graph autoencoder-based anomaly detection) |
| `pagoda/` | Implementation of **Pagoda** (another provenance-based detector) |
| `StreamSpot-Evasion-Graphs/` | Pre-generated evasion graphs for the StreamSpot dataset (zipped) |
| `Theia-Evasion-Graphs/` | Pre-generated evasion graphs for the DARPA TC3 Theia dataset — see table below |

## Getting Started

### Prerequisites

- Python 3
- `pandas`, `pickle`, `csv`, PyTorch (for FGA)

### Generating Evasion Graphs (`insertAttackPath.py`)

```bash
python insertAttackPath.py <nz>
```

Edit the `main()` call at the bottom of the file with paths to:

- An **attack path** file (pickle format, from ProvDetector output)
- A **benign graph** file (CSV with columns: `sourceId`, `sourceType`, `destinationId`, `destinationType`, `syscal`, `program`, `retTime`, `pid`, `cmdLineArgs1`, `cmdLineArgs2`)
- A **save path** for the output evasion graph

> **Note**: The `insertAttackPath.py` has hardcoded references at the bottom (`attLoc`, `benLoc`, `saveLoc`) that need to be defined with your actual file paths before running.

### Running the Detectors

#### ProvDetector

Trains on benign graphs and outputs top-K anomalous paths.

1. Prepare a CSV with format: `sourceId`, `sourceType`, `destId`, `destType`, `syscal`, `processName`, `retTime`, `pid`, `arg1`, `arg2`, `graphId`
2. Pass training and testing files to `main.py`:

```bash
python provDetector/main.py
```

#### FGA

Graph autoencoder approach for anomaly detection.

1. Prepare `adjMat.pth`, `X.pth`, `names.pth` tensors
2. Run `main` with `nz=0, train=True` to train
3. Run with `train=False, nz=0` on training data, then `nz=1` on test data
4. Compare resulting `graphEmbed-0.pth` and `graphEmbed-1.pth` with `cdist`

#### Pagoda

Frequency-based detection.

1. Prepare CSV files in `benign/`, `attack/`, `evasion/` folders
2. Run:

```bash
python pagoda/main.py
```

### Using Pre-built Datasets

#### StreamSpot

Unzip the archives in `StreamSpot-Evasion-Graphs/`:

- `tajka/trainGraphs/` — 71 benign training graphs (10-column CSV)
- `attackGraphs/` — 100 original attack graphs
- `evasion/` — 100 evasion graphs (attack + injected benign substructures)

These are used directly by ProvDetector, Pagoda, and FGA as described above.

#### DARPA TC3 Theia

The `Theia-Evasion-Graphs/` directory contains pre-generated evasion graphs for the DARPA Transparent Computing Engagement 3 (TC3) dataset. The DARPA Theia dataset describes a single provenance graph broken into 25 time-period subgraphs (~4.8M edges total) with a Firefox backdoor "Drakon" intrusion (see §II of the paper).

> **Note**: The DARPA benign training data is **not included** in this repo — it must be obtained separately from the [DARPA Transparent Computing program](https://github.com/darpa-i2o/Transparent-Computing). The files here are the evasion graphs only.

| File | Detector | Format | Description |
|------|----------|--------|-------------|
| `streamSpotTheia.zip` / `attack-6r1mil1.txt` | StreamSpot | StreamSpot (6 cols, tab-sep) | Evasion graph, ~1M edges, graph ID 23 |
| `unicornTheia.zip` / `l9attack.txt` | Unicorn | StreamSpot (6 cols, tab-sep) | Evasion graph, graph ID 11 |
| `provDetectorTheia.zip` / `evasion-provDetector.csv` | ProvDetector | ProvDetector (11-col CSV) | Evasion graph, ~10K injected edges |
| `Theia-Evasion.zip` / `attack-6r4mil1.txt` | StreamSpot | StreamSpot (6 cols, tab-sep) | Larger evasion graph variant, ~4M edges |

The `.txt` files use the StreamSpot 6-column tab-separated format: `srcID  srcType  destID  destType  syscal  graphID` (single-character type codes). The `.csv` file uses the ProvDetector 11-column format.

To test `evasion-provDetector.csv` with ProvDetector, obtain the DARPA Theia benign graphs, convert them to ProvDetector format using `parser/tcToProvParser.py`, then run:

```bash
cd provDetector
python3 main.py <theia_benign_train.csv> ../Theia-Evasion-Graphs/evasion-provDetector.csv
```
