# Running Pagoda

## 1. Prerequisites

Install the required packages:

```bash
pip3 install pandas networkx torch tqdm
```

## 2. Data Format

Pagoda expects separate CSV files per graph (one file = one provenance graph), each with 10 columns:

`srcName, srcType, destName, destType, syscal, programName, retTime, PID, cmd1, cmd2`

Organize files into 3 directories:

- `benign/` — benign training graphs
- `attack/` — original attack graphs
- `evasion/` — evasion graphs (attack + injected benign substructures)

Pre-built data already exists in the repo:

- `StreamSpot-Evasion-Graphs/tajka/trainGraphs/` — 71 benign graphs
- `StreamSpot-Evasion-Graphs/attackGraphs/` — 100 attack graphs
- `StreamSpot-Evasion-Graphs/evasion/` — 100 evasion graphs

## 3. Run

Navigate to the pagoda directory and run:

```bash
cd pagoda

python3 main.py <benign_dir> <attack_dir> <evasion_dir>
```

Example with the repo's data:

```bash
python3 main.py \
  ../StreamSpot-Evasion-Graphs/tajka/trainGraphs \
  ../StreamSpot-Evasion-Graphs/attackGraphs \
  ../StreamSpot-Evasion-Graphs/evasion
```

## 4. What It Does (Step by Step)

The pipeline in `main.py` runs 4 stages:

| Stage | File             | What it does                                                                 |
|-------|------------------|-----------------------------------------------------------------------------|
| 1     | freqDBWrapper.py | Builds a frequency database from benign graphs — counts (src, dest) pairs that appear 2+ times |
| 2     | pathsWrapper.py  | Extracts all paths (root to leaf) from each graph using NetworkX, scores edges against the frequency DB |
| 3     | thresholdWrapper.py | Computes path-level and graph-level anomaly thresholds from benign/attack scores |
| 4     | calcStatsWrapper.py | Calculates FPR, TPR, and evasion rate                                      |

## 5. Output

The console prints:

```
fpr: 0, tpr: 1, evasion: 1
```

| Metric  | Meaning                                                                 |
|---------|-------------------------------------------------------------------------|
| fpr     | False Positive Rate — how many benign graphs were incorrectly flagged  |
| tpr     | True Positive Rate — how many attack graphs were correctly detected    |
| evasion | How many evasion graphs were detected (lower = evasion more successful) |

It also caches intermediate results as `.pth` files:

| File             | Contents                              |
|------------------|---------------------------------------|
| freqDB.pth       | Frequency database                    |
| scores-ben.pth   | Graph-level anomaly scores for benign data |
| scores-att.pth   | Graph-level anomaly scores for attack data |
| scores-ev.pth    | Graph-level anomaly scores for evasion data |
| pathScores-*.pth | Per-path anomaly scores                |
| results.pth      | Thresholds and cached results          |

## 6. Clean Run

Delete cached files if you change the input data:

```bash
rm -f freqDB.pth results.pth scores-*.pth pathScores-*.pth
```

## 7. How Pagoda Detects Anomalies

1. **Edge rarity**: If an edge (src, dest) is NOT in the frequency database, it gets a score of 1; otherwise 0
2. **Path anomaly score**: Average rarity across all edges in a path
3. **Path-level threshold**: If any path's score exceeds the threshold, the graph is flagged at the path level
4. **Graph anomaly score**: Weighted sum of all path scores (weighted by normalized path length)
5. **Graph-level threshold**: If the graph score exceeds the threshold, the graph is anomalous

## 8. Quick Test (Small Subset)

To run faster with fewer graphs:

```bash
mkdir -p /tmp/pagoda_ben /tmp/pagoda_att /tmp/pagoda_ev

# Copy 3 benign, 1 attack, 1 evasion
cp ../StreamSpot-Evasion-Graphs/tajka/trainGraphs/output_ADM-30{1,2,3}.csv /tmp/pagoda_ben/
cp ../StreamSpot-Evasion-Graphs/attackGraphs/output_ADM-500.csv /tmp/pagoda_att/
cp ../StreamSpot-Evasion-Graphs/evasion/output_ADM-600.csv /tmp/pagoda_ev/

python3 main.py /tmp/pagoda_ben /tmp/pagoda_att /tmp/pagoda_ev
```

## 9. Note on Runtime

Pagoda enumerates all simple paths in each graph (root to leaf). For large graphs (100K+ edges), this can take several minutes per graph and generates millions of paths. The progress bar (tqdm) shows progress per graph. Using the full 71 training + 100 attack + 100 evasion graphs will take a significant amount of time.