# How to Read Results

## Quick Way — Use the Reader Script

```bash
python3 read_results.py              # all systems
python3 read_results.py provdetector # ProvDetector only
python3 read_results.py pagoda       # Pagoda only
python3 read_results.py fga          # FGA only
```

## What Each Result Means

### ProvDetector
Outputs the top-K most anomalous paths:
- **Regularity score**: More negative = more anomalous. Paths with rare edges (not in the frequency database) get lower scores
- **Path length**: Number of edges in the path. The evasion graph has paths of 1,284 edges mixing attack and benign activity

### Pagoda
Outputs graph-level anomaly scores:
- **Benign scores**: 0.092 - 0.103 (low = normal)
- **Attack score**: 0.568 (high = anomalous, clearly above threshold 0.104)
- **Evasion score**: 0.446 (still above threshold with only 3 training graphs — evasion detected)
- With full training data (71+ graphs), evasion graphs score below the threshold and evade detection

### FGA
Outputs embedding vectors per graph:
- Compare test embeddings to training embeddings using `torch.cdist`
- Minimum distance = anomaly score. Higher = more anomalous

## Manual Inspection (Python)

### ProvDetector
```python
import pickle
kpaths = pickle.load(open('/tmp/pd_train.csv_kpathsTrainingGraphs.data', 'rb'))
```

### Pagoda
```python
import torch
scores = torch.load('pagoda/scores-att.pth', weights_only=False)
results = torch.load('pagoda/results.pth', weights_only=False)
pathThreshold, graphThreshold, benPaths, attPaths, attCaught = results
```

### FGA (After Running)
```python
import torch
train_emb = torch.load('FGA/graphEmbed-0.pth')
test_emb = torch.load('FGA/graphEmbed-1.pth')
anomaly_scores = torch.cdist(test_emb, train_emb).min(dim=1).values
```