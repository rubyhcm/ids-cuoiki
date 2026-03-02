# Research Report: Mimicry Attacks against Provenance Graph Host Intrusion Detection Systems

## Paper Information

- **Title**: "Sometimes, You Aren't What You Do: Mimicry Attacks against Provenance Graph Host Intrusion Detection Systems"
- **Authors**: Akul Goyal, Xueyuan Han, Gang Wang, Adam Bates
- **Venue**: NDSS Symposium 2023 (Network and Distributed System Security)
- **Institutions**: University of Illinois at Urbana-Champaign, Wake Forest University

---

## 1. Problem Statement

Provenance-based Host Intrusion Detection Systems (Prov-HIDS) use provenance graphs — causal dependency graphs describing the history of system execution — to detect intrusions. While these systems show promise, their robustness against adaptive adversaries has not been proven. This paper investigates whether **mimicry attacks** (a classic evasion technique) can defeat modern graph-based Prov-HIDS.

## 2. Key Concepts

### Provenance Graphs
A provenance graph G = (V, E) where vertices represent system entities (files, processes, sockets) and edges represent system events (system calls). These graphs capture the causal relationships between system activities.

### Prov-HIDS Classification Pipeline
All Prov-HIDS follow a common pattern:
1. **Deconstruct** the graph into substructures (neighborhoods, paths, or subgraphs)
2. **Encode** substructures into fixed-length vector embeddings
3. **Compare** embeddings against a trained model of benign behavior
4. **Classify** as anomalous if the distance exceeds a threshold

### Mimicry Attacks
The attacker injects benign-looking process activities into the attack graph to camouflage the attack subgraph, causing the Prov-HIDS to misclassify the evasion graph as benign.

## 3. Exemplar Systems Evaluated

| System | Method | Learning Task | Approach |
|--------|--------|--------------|----------|
| **StreamSpot** | Unsupervised | Neighborhood-based Whole Graph | StreamHash embedding + cosine similarity clustering |
| **Unicorn** | Unsupervised | Neighborhood-based Whole Graph | HistoSketch + Jaccard similarity temporal modeling |
| **ProvDetector** | Unsupervised | Path-based Subgraph | Doc2Vec path embedding + Local Outlier Factor |
| **Pagoda** | Unsupervised | Path-based Whole Graph | Frequency database + rarity-based anomaly scoring |
| **FGA** (Full Graph Autoencoder) | Unsupervised | Whole Graph Autoencoder | GCN encoder + reconstruction loss |

## 4. Mimicry Gadgets (Evasion Tactics)

### Gadget 1: Abusing Unweighted Graph Encoding
- **Target**: StreamSpot, Pagoda
- **Method**: Add batches of benign substructures to dilute the significance of anomalous substructures
- **Principle**: Unweighted encoding treats all substructures equally; adding enough benign ones shifts the embedding within the benign decision boundary

### Gadget 2: Abusing Distributional Graph Encoding
- **Target**: Unicorn, FGA, Pagoda
- **Method**: Profile the frequency distribution of benign substructures and replicate that distribution in the attack graph
- **Principle**: Match the substructure distribution to make the attack graph's embedding indistinguishable from benign graphs

### Gadget 3: Abusing Downsampled Graph Encoding
- **Target**: ProvDetector
- **Method**: Insert low-regularity benign paths to exploit the gap between the downsampling function and the distance metric
- **Principle**: ProvDetector only examines top-K lowest regularity paths; injecting benign paths with lower regularity pushes attack paths out of the K-window

## 5. Experimental Results

### Datasets
| Dataset | Nodes | Edges | Graphs | Attacks |
|---------|-------|-------|--------|---------|
| StreamSpot | 822,998 | 27,792,491 | 600 | 1 |
| DARPA TC3 THEIA | 3,721,210 | 46,303,154 | 25 | 4 |

### Evasion Success (100% across all systems)

| System | StreamSpot Dataset | DARPA Dataset | Edges Added |
|--------|-------------------|---------------|-------------|
| StreamSpot | 100% evasion | 100% evasion | 250K-300K (SS), 80K (DARPA) |
| Unicorn | 100% evasion | 100% evasion | 40K (SS), 80K (DARPA) |
| ProvDetector | 100% evasion | 100% evasion | 9K (SS), 10K (DARPA) |
| Pagoda | 100% evasion | 100% evasion | ~20K |
| FGA | 100% evasion | 100% evasion | ~80K |

### Gadget Composability (DARPA Dataset)
Combining Gadget 2 + Gadget 3 can simultaneously evade StreamSpot, Unicorn, and ProvDetector.

### Robustness to Parameter Changes
Evasion remains effective even when the Prov-HIDS's parameters are changed from their recommended values.

### Runtime Performance
Total evasion generation time: **~1.82 seconds** (vs. RL-S2V which required 7 days and failed).

## 6. Repository Execution Results

We executed the repository's implementations against the StreamSpot dataset:

### ProvDetector Run
- **Training data**: 3 benign graphs from StreamSpot (CNN browsing activity)
- **Test data**: 1 evasion graph (graph ID 200)
- **Result**: 20 anomalous paths extracted (K=20)
- **Path length**: Up to 1,284 edges per path
- **Regularity score**: -15,053.11 (highly anomalous paths detected in the evasion graph)
- The evasion graph's paths include both attack edges (e.g., connections to suspicious IPs) and injected benign substructures (Firefox browsing activity)

### Pagoda Run
- **Training data**: 3 benign graphs
- **Attack data**: 1 original attack graph
- **Evasion data**: 1 evasion graph
- **Result**: `fpr: 0, tpr: 1, evasion: 1`
  - False Positive Rate: 0 (no benign graphs flagged)
  - True Positive Rate: 1 (attack graph correctly detected)
  - Evasion: 1 (evasion graph was still detected with this small training set)
- **Note**: With only 3 training graphs, the evasion was detected. The paper demonstrates that with full training data (71+ benign graphs), the evasion achieves 100% success rate.

### Pre-built Theia Evasion Graphs

The `Theia-Evasion-Graphs/` directory contains pre-generated evasion graphs for the DARPA TC3 Theia dataset (Drakon Firefox backdoor attack):

| File | Detector | Edges Added |
|------|----------|-------------|
| `attack-6r1mil1.txt` / `streamSpotTheia.zip` | StreamSpot | ~80K (1M total edges, graph ID 23) |
| `l9attack.txt` / `unicornTheia.zip` | Unicorn | ~80K (graph ID 11) |
| `evasion-provDetector.csv` / `provDetectorTheia.zip` | ProvDetector | ~10K injected |
| `attack-6r4mil1.txt` / `Theia-Evasion.zip` | StreamSpot (larger variant) | ~4M total edges |

The `.txt` files use 6-column tab-separated StreamSpot format. The `.csv` file uses 11-column ProvDetector format. The DARPA benign training data is not included in the repo and must be obtained separately.

## 7. Key Contributions

1. **Mimicry attacks are effective against modern Prov-HIDS**: 100% evasion rate across all five systems
2. **Systemic vulnerabilities identified**: The design choices in graph decomposition, encoding, and comparison create exploitable weaknesses
3. **Practical feasibility demonstrated**: Evasion graphs generated in under 2 seconds; live attack demonstration successful
4. **Outperforms domain-general approaches**: RL-S2V (reinforcement learning) failed after 7 days; this approach succeeds consistently
5. **Open-source benchmark**: Code and datasets publicly available for future Prov-HIDS evaluation

## 8. Potential Mitigations (from Discussion)

- Move toward **lower-level graph classification** (nodes, edges, subgraphs) rather than whole-graph
- Incorporate **provenance-based causal analysis** that leverages temporal and causal properties
- Develop **finer-grained behavioral detection** aligned with commercial endpoint detection products
- Consider **root cause and impact analysis** in the classification pipeline

## 9. Conclusion

This work demonstrates that mimicry attacks remain a fundamental threat to provenance-based intrusion detection. The systematic design choices in all evaluated Prov-HIDS — graph decomposition, vectorization, and bounded comparison — create exploitable gaps that allow adversaries to inject benign substructures and evade detection with 100% success rate. The approach is efficient (< 2 seconds), practical (demonstrated in live attacks), and generalizable across multiple detection paradigms.

---

*Report generated from the NDSS 2023 paper and execution of the mimicry-provenance-generator repository.*
