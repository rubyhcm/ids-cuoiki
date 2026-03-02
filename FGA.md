# Running FGA (Full Graph Autoencoder)

## 1. Prerequisites

Install the required packages:

```bash
pip3 install torch torch-geometric
```

torch-geometric (PyG) is required for GCNConv, ARGVA, and Planetoid. Install it following [https://pytorch-geometric.readthedocs.io/en/latest/install/installation.html](https://pytorch-geometric.readthedocs.io/en/latest/install/installation.html) matching your torch/CUDA version.

## 2. Prepare Input Data

FGA needs 3 PyTorch tensor files in a single directory (`homePath`):

| File       | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| adjMat.pth | Edge index tensor of shape [2, num_edges] — row 0 = source node IDs, row 1 = destination node IDs |
| X.pth      | Feature tensor of shape [num_nodes, feature_dim] — use zeros if no features available |
| names.pth  | List of tuples: ((node_name, node_type), graphID) — ordered by graphID     |

All data must be sorted by graphID (edges for graph 1 before graph 2, etc.).

Example generation script from CSV data:

```python
import torch, pandas as pd, os

data_dir = "StreamSpot-Evasion-Graphs/tajka/trainGraphs"
output_dir = "/tmp/fga_data"
os.makedirs(output_dir, exist_ok=True)

all_edges_src, all_edges_dst = [], []
all_names = []
node_map = {}
node_idx = 0

for gid, f in enumerate(sorted(os.listdir(data_dir))[:5]):  # first 5 graphs
    df = pd.read_csv(os.path.join(data_dir, f),
        names=['srcName','srcType','destName','destType','syscal',
               'programName','retTime','PID','cmd1','cmd2'])
    for _, row in df.iterrows():
        src_key = (str(row['srcName']).strip(), str(row['srcType']).strip())
        dst_key = (str(row['destName']).strip(), str(row['destType']).strip())
        for key in [src_key, dst_key]:
            if (key, gid) not in node_map:
                node_map[(key, gid)] = node_idx
                all_names.append((key, gid))
                node_idx += 1
        all_edges_src.append(node_map[(src_key, gid)])
        all_edges_dst.append(node_map[(dst_key, gid)])

edges = torch.tensor([all_edges_src, all_edges_dst], dtype=torch.long)
X = torch.zeros(node_idx, 16)  # 16-dim zero features
names = all_names

torch.save(edges, f"{output_dir}/adjMat.pth")
torch.save(X, f"{output_dir}/X.pth")
torch.save(names, f"{output_dir}/names.pth")
print(f"Nodes: {node_idx}, Edges: {len(all_edges_src)}, Graphs: {gid+1}")
```

## 3. Run (3-Step Process)

Navigate to the FGA directory and run the following steps:

```bash
cd FGA

# Step 1: Train the autoencoder on benign graphs
python3 autoencoder.py 0 /tmp/fga_data 0 4 true 0 4
#                       ^nz ^homePath   ^trainStart ^trainEnd ^train ^testStart ^testEnd
# python3 autoencoder.py 0 /tmp/fga_data 0 70 true 0 70

# Step 2: Generate embeddings for TRAINING graphs (nz=0)
python3 autoencoder.py 0 /tmp/fga_data 0 4 false 0 4
# Output: graphEmbed-0.pth (baseline benign embeddings)

# Step 3: Generate embeddings for TEST graphs (nz=1)
python3 autoencoder.py 1 /tmp/fga_data 0 4 false 5 10
#                                                   ^testStart ^testEnd (your test graph IDs)
# Output: graphEmbed-1.pth (test graph embeddings)
```

## 4. Compare Embeddings (Anomaly Detection)

Use Python to compare embeddings:

```python
import torch

train_embed = torch.load('graphEmbed-0.pth')  # benign baseline
test_embed = torch.load('graphEmbed-1.pth')   # test graphs

# Compute pairwise distances
distances = torch.cdist(test_embed, train_embed)

# Minimum distance to any benign graph = anomaly score
anomaly_scores = distances.min(dim=1).values
print("Anomaly scores:", anomaly_scores)
# Higher score = more anomalous
```

## 5. Summary of CLI Arguments

```
python3 autoencoder.py <nz> <homePath> <trainStart> <trainEnd> <train> <testStart> <testEnd>
```

| Arg       | Description                                      |
|-----------|--------------------------------------------------|
| nz        | Embedding ID (0 for train embeddings, 1 for test) |
| homePath  | Directory containing adjMat.pth, X.pth, names.pth |
| trainStart| First graph ID for training                      |
| trainEnd  | Last graph ID for training                       |
| train     | true to train, false to generate embeddings      |
| testStart | First graph ID for testing                       |
| testEnd   | Last graph ID for testing                        |