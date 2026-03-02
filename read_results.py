#!/usr/bin/env python3
"""
Result Reader for Mimicry Provenance Generator
===============================================
Reads and displays results from ProvDetector, Pagoda, and FGA.

Usage:
    python3 read_results.py                  # read all available results
    python3 read_results.py provdetector     # read only ProvDetector results
    python3 read_results.py pagoda           # read only Pagoda results
    python3 read_results.py fga              # read only FGA results
"""

import os
import sys
import pickle
import glob

def read_provdetector():
    print("=" * 70)
    print("PROVDETECTOR RESULTS")
    print("=" * 70)

    # 1. Frequency Database
    freq_path = "provDetector/freqList.data"
    if os.path.exists(freq_path):
        freqDict = pickle.load(open(freq_path, 'rb'))
        print(f"\n[Frequency Database] {freq_path}")
        print(f"  Total unique (source, syscall) pairs: {len(freqDict)}")
        # Show top 5 entries
        count = 0
        for key, val in list(freqDict.items())[:5]:
            src, syscall = key
            destinations = {k: v for k, v in val.items() if k != 'total'}
            print(f"  ({src}, {syscall}) -> {len(destinations)} destinations, total count: {val['total']}")
            count += 1
        if len(freqDict) > 5:
            print(f"  ... and {len(freqDict) - 5} more entries")
    else:
        print(f"\n[Frequency Database] Not found at {freq_path}")

    # 2. Set of Sets (node sets per graph)
    sets_path = "provDetector/setOfsets.data"
    if os.path.exists(sets_path):
        setOfsets = pickle.load(open(sets_path, 'rb'))
        print(f"\n[Node Sets] {sets_path}")
        print(f"  Number of training graphs: {len(setOfsets)}")
        for i, (src_set, dst_set) in enumerate(setOfsets):
            print(f"  Graph {i}: {len(src_set)} source nodes, {len(dst_set)} destination nodes")
    else:
        print(f"\n[Node Sets] Not found at {sets_path}")

    # 3. K-Paths (anomalous paths from test graphs)
    kpath_files = glob.glob("/tmp/*kpaths*.data") + glob.glob("provDetector/*kpaths*.data") + glob.glob("*kpaths*.data")
    kpath_files = list(set(kpath_files))
    if kpath_files:
        for kpath_file in kpath_files:
            data = pickle.load(open(kpath_file, 'rb'))
            print(f"\n[K-Paths] {kpath_file}")
            print(f"  Number of test graphs: {len(data)}")
            for gname, kpaths in data:
                print(f"\n  --- Graph ID: {gname} ---")
                print(f"  Anomalous paths found (K): {len(kpaths)}")
                if not kpaths:
                    print("  No anomalous paths detected.")
                    continue

                scores = [kp[1] for kp in kpaths]
                print(f"  Regularity score range: [{min(scores):.4f}, {max(scores):.4f}]")
                print(f"  Average regularity score: {sum(scores)/len(scores):.4f}")
                print(f"  Is DAG: {kpaths[0][2]}")

                # Show top 3 most anomalous paths
                for idx, kp in enumerate(kpaths[:3]):
                    path, score, is_dag = kp
                    print(f"\n  Path {idx+1} (score: {score:.4f}, length: {len(path)} edges):")
                    # Show first 3 edges
                    for edge in path[:3]:
                        src_node = edge[0]
                        syscall_info = edge[1]
                        dst_node = edge[2]
                        print(f"    {_fmt_node(src_node)} --[{syscall_info}]--> {_fmt_node(dst_node)}")
                    if len(path) > 3:
                        print(f"    ... ({len(path) - 3} more edges)")
                if len(kpaths) > 3:
                    print(f"\n  (Showing 3 of {len(kpaths)} paths)")
    else:
        print(f"\n[K-Paths] No kpaths files found. Run ProvDetector first.")

    print()


def read_pagoda():
    import torch

    print("=" * 70)
    print("PAGODA RESULTS")
    print("=" * 70)

    # 1. Frequency Database
    freq_path = "pagoda/freqDB.pth"
    if os.path.exists(freq_path):
        freqDB = torch.load(freq_path, weights_only=False)
        print(f"\n[Frequency Database] {freq_path}")
        print(f"  Frequent (src, dest) pairs: {len(freqDB)}")
        for pair in list(freqDB)[:5]:
            print(f"  {pair}")
        if len(freqDB) > 5:
            print(f"  ... and {len(freqDB) - 5} more pairs")
    else:
        print(f"\n[Frequency Database] Not found at {freq_path}")

    # 2. Graph-level Anomaly Scores
    for name, label in [("ben", "Benign"), ("att", "Attack"), ("ev", "Evasion")]:
        score_path = f"pagoda/scores-{name}.pth"
        if os.path.exists(score_path):
            scores = torch.load(score_path, weights_only=False)
            print(f"\n[Graph Anomaly Scores - {label}] {score_path}")
            print(f"  Number of graphs: {len(scores)}")
            if scores:
                t = torch.FloatTensor(scores)
                print(f"  Min score:  {t.min().item():.6f}")
                print(f"  Max score:  {t.max().item():.6f}")
                print(f"  Mean score: {t.mean().item():.6f}")
                print(f"  Scores: {[f'{s:.6f}' for s in scores[:10]]}")
                if len(scores) > 10:
                    print(f"  ... ({len(scores) - 10} more)")

    # 3. Path-level Anomaly Scores
    for name, label in [("ben", "Benign"), ("att", "Attack"), ("ev", "Evasion")]:
        path_score_path = f"pagoda/pathScores-{name}.pth"
        if os.path.exists(path_score_path):
            path_scores = torch.load(path_score_path, weights_only=False)
            print(f"\n[Path Anomaly Scores - {label}] {path_score_path}")
            print(f"  Number of graphs: {len(path_scores)}")
            for i, graph_scores in enumerate(path_scores[:3]):
                t = torch.FloatTensor(graph_scores)
                print(f"  Graph {i}: {len(graph_scores)} paths, "
                      f"min={t.min().item():.6f}, max={t.max().item():.6f}, mean={t.mean().item():.6f}")
            if len(path_scores) > 3:
                print(f"  ... ({len(path_scores) - 3} more graphs)")

    # 4. Thresholds and Final Results
    results_path = "pagoda/results.pth"
    if os.path.exists(results_path):
        pathThreshold, graphThreshold, benPaths, attPaths, attCaught = torch.load(results_path, weights_only=False)
        print(f"\n[Thresholds & Results] {results_path}")
        print(f"  Path-level threshold:  {pathThreshold:.6f}")
        print(f"  Graph-level threshold: {graphThreshold:.6f}")
        print(f"  Attack graphs caught at path level: {attCaught}")
        print(f"\n  Interpretation:")
        print(f"    - Paths with anomaly score >= {pathThreshold:.6f} are flagged")
        print(f"    - Graphs with graph anomaly score >= {graphThreshold:.6f} are flagged")
        print(f"    - {attCaught} attack graph(s) caught by path-level threshold alone")

        # Recalculate final metrics
        ben_t = torch.FloatTensor(benPaths)
        att_t = torch.FloatTensor(attPaths)
        fpr = torch.sum(ben_t >= graphThreshold).item()
        tpr = torch.sum(att_t >= graphThreshold).item() + attCaught
        print(f"\n  Final Metrics:")
        print(f"    FPR (benign flagged as attack): {fpr}/{len(benPaths)}")
        print(f"    TPR (attacks detected):         {tpr}")

        # Check evasion if available
        ev_score_path = "pagoda/scores-ev.pth"
        if os.path.exists(ev_score_path):
            ev_scores = torch.load(ev_score_path, weights_only=False)
            ev_t = torch.FloatTensor(ev_scores)
            ev_caught = torch.sum(ev_t >= graphThreshold).item()
            ev_total = len(ev_scores)
            ev_evaded = ev_total - ev_caught
            print(f"    Evasion graphs detected:        {ev_caught}/{ev_total}")
            print(f"    Evasion graphs EVADED:          {ev_evaded}/{ev_total} ({ev_evaded/ev_total*100:.1f}% evasion rate)")
    else:
        print(f"\n[Thresholds] Not found at {results_path}")

    print()


def read_fga():
    import torch

    print("=" * 70)
    print("FGA (FULL GRAPH AUTOENCODER) RESULTS")
    print("=" * 70)

    # Look for graphEmbed files
    embed_files = sorted(glob.glob("FGA/graphEmbed-*.pth") + glob.glob("graphEmbed-*.pth"))
    if not embed_files:
        print("\n  No graphEmbed-*.pth files found.")
        print("  Run FGA first to generate embeddings (see README).")
        print()
        return

    embeddings = {}
    for f in embed_files:
        emb = torch.load(f, weights_only=False)
        nz = f.split("graphEmbed-")[1].replace(".pth", "")
        embeddings[nz] = emb
        print(f"\n[Embeddings] {f}")
        print(f"  nz={nz}, shape: {emb.shape}")
        print(f"  Number of graphs: {emb.shape[0]}")
        print(f"  Embedding dimension: {emb.shape[1]}")
        print(f"  Embedding norm range: [{emb.norm(dim=1).min().item():.4f}, {emb.norm(dim=1).max().item():.4f}]")

    # Compare embeddings if both exist
    if "0" in embeddings and "1" in embeddings:
        train_emb = embeddings["0"]  # benign baseline
        test_emb = embeddings["1"]   # test graphs

        distances = torch.cdist(test_emb, train_emb)
        min_distances = distances.min(dim=1).values

        print(f"\n[Anomaly Detection]")
        print(f"  Comparing {test_emb.shape[0]} test graphs against {train_emb.shape[0]} training graphs")
        print(f"  Distance metric: Euclidean (cdist)")
        print(f"\n  Anomaly scores (min distance to nearest benign graph):")
        for i, score in enumerate(min_distances):
            print(f"    Test graph {i}: {score.item():.6f}")
        print(f"\n  Min anomaly score: {min_distances.min().item():.6f}")
        print(f"  Max anomaly score: {min_distances.max().item():.6f}")
        print(f"  Mean anomaly score: {min_distances.mean().item():.6f}")
        print(f"\n  Interpretation:")
        print(f"    Higher score = more anomalous (farther from benign graphs)")
        print(f"    To classify: set a threshold from validation data")
    elif len(embeddings) == 1:
        print(f"\n  Only one embedding file found. Need both graphEmbed-0.pth (train)")
        print(f"  and graphEmbed-1.pth (test) to compute anomaly scores.")

    # Check for autoencoder model
    model_path = "FGA/autoencoder2.pth"
    if os.path.exists(model_path):
        size_mb = os.path.getsize(model_path) / (1024 * 1024)
        print(f"\n[Trained Model] {model_path} ({size_mb:.2f} MB)")
    else:
        print(f"\n[Trained Model] Not found. Run FGA with train=true first.")

    print()


def _fmt_node(node):
    """Format a node for display, truncating long names."""
    s = str(node)
    if len(s) > 60:
        return s[:57] + "..."
    return s


def main():
    os.chdir("/home/loinguyen/agrios/mimicry-provenance-generator")

    target = sys.argv[1].lower() if len(sys.argv) > 1 else "all"

    print()
    print("Mimicry Provenance Generator — Result Reader")
    print("=" * 70)

    if target in ("all", "provdetector", "pd"):
        read_provdetector()

    if target in ("all", "pagoda"):
        try:
            read_pagoda()
        except ImportError:
            print("  [ERROR] torch is required to read Pagoda results")
            print()

    if target in ("all", "fga"):
        try:
            read_fga()
        except ImportError:
            print("  [ERROR] torch is required to read FGA results")
            print()

    if target == "all":
        print("=" * 70)
        print("TIP: Run with argument 'provdetector', 'pagoda', or 'fga' to see")
        print("     results for a specific system only.")
        print("=" * 70)


if __name__ == "__main__":
    main()
