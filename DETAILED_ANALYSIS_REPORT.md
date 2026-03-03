# Báo Cáo Phân Tích Chi Tiết: Tấn Công Mimicry chống lại Hệ Thống Phát Hiện Xâm Nhập Dựa Trên Provenance Graph

*Dataset: StreamSpot | Ngày: Tháng 3/2026*

<!-- Cấu trúc báo cáo

1. Tổng quan nghiên cứu — Dataset StreamSpot, 3 gadget tấn công, bối cảnh
2. Kiến trúc hệ thống — Pipeline insertAttackPath.py chi tiết từ source code, định dạng dữ liệu
3. Cơ chế tấn công mimicry — Nguyên lý toán học, ràng buộc thực tế
4. Phân tích từng detector:
    - ProvDetector: Giải thích score −483.77, tại sao Gadget 3 chưa xác nhận được (thiếu Doc2Vec+LOF)
    - Pagoda: Phân tích chi tiết tại sao 3/20 graphs thất bại vs 71 graphs thành công — vấn đề frequency DB coverage, bottleneck runtime O(exponential)
    - FGA: Giải thích tại sao GCN aggregation dễ bị kéo về benign cluster, phân tích embedding norms
5. Nguyên nhân gốc rễ — Closed-world assumption, linear aggregation, asymmetry attacker/defender
6. Điểm yếu chung — Thiếu semantic reasoning, threshold sensitivity
7. Hướng tiếp cận tương lai:
    - Defense: Attack core isolation, causal consistency, per-process behavior, temporal anomaly, robust aggregation
    - Research: Grey/black-box evaluation, adversarial training, graph watermarking, information-theoretic bounds
    - Engineering: Hoàn thiện ProvDetector pipeline, optimize Pagoda runtime, full-scale FGA experiment -->

---

## Mục Lục

1. [Tổng Quan Nghiên Cứu](#1-tổng-quan-nghiên-cứu)
2. [Kiến Trúc Hệ Thống](#2-kiến-trúc-hệ-thống)
3. [Cơ Chế Tấn Công Mimicry](#3-cơ-chế-tấn-công-mimicry)
4. [Phân Tích Từng Hệ Thống Phát Hiện](#4-phân-tích-từng-hệ-thống-phát-hiện)
   - [4.1 ProvDetector](#41-provdetector)
   - [4.2 Pagoda](#42-pagoda)
   - [4.3 FGA (Full Graph Autoencoder)](#43-fga-full-graph-autoencoder)
5. [Phân Tích Nguyên Nhân Kết Quả](#5-phân-tích-nguyên-nhân-kết-quả)
6. [Điểm Yếu Chung Của Các Hệ Thống](#6-điểm-yếu-chung-của-các-hệ-thống)
7. [Hướng Tiếp Cận Tương Lai](#7-hướng-tiếp-cận-tương-lai)
8. [Kết Luận](#8-kết-luận)

---

## 1. Tổng Quan Nghiên Cứu

### 1.1 Bối Cảnh

Các hệ thống phát hiện xâm nhập (IDS) dựa trên **provenance graph** phân tích luồng thông tin giữa các tiến trình, tệp, và socket trên hệ điều hành thông qua system call. Thay vì phát hiện chữ ký tấn công cụ thể, chúng xây dựng mô hình hành vi bình thường của hệ thống và phát hiện các **bất thường** (anomalies) trong đồ thị quan hệ.

Nghiên cứu này kiểm tra một câu hỏi quan trọng: **Liệu kẻ tấn công có thể ngụy trang hành vi độc hại thành hành vi bình thường để qua mặt các IDS này không?**

### 1.2 Dataset StreamSpot

Dataset StreamSpot thu thập system call trace từ máy chủ Linux qua SystemTap:

| Loại | Số đồ thị | ID đồ thị | Cạnh TB/đồ thị |
|------|-----------|-----------|----------------|
| Benign training | 71 | 0–70 | ~66K |
| Attack test | 100 | 200–299 | ~5.6K |
| Evasion test | 100 | 400–499 | ~121K |

**5 kịch bản benign**: YouTube, CNN, downloading, email, game (dùng trình duyệt Firefox).
**Kịch bản tấn công**: Drive-by-download Flash exploit qua Firefox — đây là điểm khai thác quan trọng vì **cả benign lẫn attack đều dùng Firefox làm điểm khởi đầu**.

### 1.3 Ba "Gadget" Tấn Công

Bài báo gốc định nghĩa ba kỹ thuật tấn công mimicry:

| Gadget | Tên | Cơ Chế |
|--------|-----|---------|
| Gadget 1 | Frequency dilution | Tiêm các cạnh benign có tần suất cao để "pha loãng" tỷ lệ cạnh hiếm |
| Gadget 2 | Distributional encoding abuse | Tiêm subgraph benign để kéo embedding về phía cụm benign |
| Gadget 3 | Downsampled encoding abuse | Tiêm đủ nhiều path benign để đẩy attack path ra khỏi top-K window |

---

## 2. Kiến Trúc Hệ Thống

### 2.1 Pipeline Tạo Evasion Graph (`insertAttackPath.py`)

```
Attack Path (pickle)  ──┐
                        ├──► insertAttackPath() ──► Evasion Graph CSV
Benign Graph (CSV)    ──┘
```

**Quy trình chi tiết** (phân tích từ source code):

1. **Tải attack path**: `getAttackPath()` load pickle từ ProvDetector output, sắp xếp theo timestamp.

2. **Tìm điểm chèn**: `findInsertPoint()` tìm tiến trình Firefox trong benign graph — điểm chèn tự nhiên vì tấn công cũng đi qua Firefox.

3. **Chiếm quyền tiến trình** (`takeOver()`): Tạo PID mới, điều chỉnh timestamps của các cạnh trước điểm chèn với khoảng cách `inter = 40255518` để duy trì tính hợp lệ về thời gian.

4. **Chèn attack path** (`insertAttackPath()`):
   - Splice các cạnh tấn công vào đồ thị
   - Map PID để tránh xung đột
   - Thêm các thao tác "clone" để giả lập fork tiến trình hợp lệ

5. **Chèn benign substructures** (`insertBenSubstructs()`): Thêm các cấu trúc con benign xung quanh attack path để ngụy trang.

6. **Lưu evasion graph**: CSV 10 cột, có thể xử lý bởi cả ba detector.

**Kết quả**: Evasion graph có ~121K cạnh (so với ~5.6K của attack graph gốc), phần lớn là benign substructures được chèn vào.

### 2.2 Định Dạng Dữ Liệu

```
sourceId, sourceType, destinationId, destinationType, syscal,
program, retTime, pid, cmdLineArgs1, cmdLineArgs2 [, graphId]
```

Node types: `p` (process), `f` (file), `s` (socket)
ProvDetector thêm cột `graphId` (11 cột) để phân biệt đồ thị trong file ghép.

---

## 3. Cơ Chế Tấn Công Mimicry

### 3.1 Nguyên Lý Cơ Bản

Tất cả ba detector đều học **phân phối hành vi benign** từ tập huấn luyện, sau đó phát hiện các graph "xa lạ" với phân phối đó. Tấn công mimicry khai thác giả thuyết rằng: **nếu làm cho đồ thị trông giống benign hơn, điểm anomaly sẽ giảm xuống dưới ngưỡng phát hiện**.

### 3.2 Tại Sao Cách Tiếp Cận Này Hoạt Động Về Mặt Lý Thuyết

```
Benign distribution: B (training)
Attack graph:        A (clearly out-of-distribution)
Evasion graph:       E = A ∪ large(B')  where B' ⊂ B

If |B'| >> |A|, then score(E) ≈ score(B') ≈ score(B)
```

Khi số cạnh benign được chèn vào đủ lớn, tín hiệu của attack path bị "át" bởi tín hiệu benign.

### 3.3 Ràng Buộc Thực Tế

- Evasion graph phải **có nghĩa về ngữ nghĩa**: timestamps phải hợp lệ, PID phải nhất quán.
- Attack path phải **được kết nối vào đồ thị**: không thể chỉ thêm cạnh ngẫu nhiên.
- Kẻ tấn công cần **biết phân phối benign** để chèn đúng loại cạnh.

---

## 4. Phân Tích Từng Hệ Thống Phát Hiện

---

### 4.1 ProvDetector

#### Cơ Chế Hoạt Động

ProvDetector là hệ thống phát hiện **path-based subgraph**:

**Bước 1 — Xây dựng Frequency Database** (`freqDB.py`):
```python
freqDict = {(src, syscal): {dest: count, 'total': total}, ...}
setOfsets = [[sources_set_i, dests_set_i] for i in graphs]
```

**Bước 2 — Tính Anomaly Score** cho mỗi cạnh:
```
score(edge) = -log2(inScore × freqScore × outScore)
```
Trong đó:
- `inScore` = tỷ lệ đồ thị training có chứa source node
- `outScore` = tỷ lệ đồ thị training có chứa dest node
- `freqScore` = P(dest | src, syscal) — xác suất chuyển tiếp có điều kiện

**Bước 3 — Tìm K=20 path bất thường nhất**: Dùng NetworkX tìm K shortest paths trong DAG được xây dựng từ provenance graph (sắp xếp theo timestamp).

**Bước 4 — Tính Regularity Score** của path: tổng các edge scores.

**Bước 5 — Doc2Vec + LOF** (closed-source): Encode top-K paths thành vector, áp dụng Local Outlier Factor để phân loại. **Bước này KHÔNG được implement trong repo này.**

#### Kết Quả và Phân Tích Nguyên Nhân

**Attack graphs (100/100 phát hiện được)**:
- Regularity score = **−483.77** (đồng nhất trên tất cả 100 đồ thị)
- Score âm lớn = rất bất thường

*Nguyên nhân*: Attack path chứa các cạnh cực kỳ hiếm — các system call từ Firefox đến các tệp/socket không bao giờ xuất hiện trong training data. Công thức `-log2(p)` với p rất nhỏ → score rất âm.

**Evasion graphs (100/100 vẫn bị phát hiện ở bước regularity)**:
- Top-path regularity score = **−483.77** (giống attack)
- Mean top-path length = **32 edges** (vs attack path length)

*Nguyên nhân*: Gadget 3 hoạt động bằng cách tiêm nhiều path benign có regularity score *thấp hơn* (bình thường hơn) attack path. Mục tiêu là **đẩy attack path ra khỏi top-K window**.

Tuy nhiên, ở bước regularity score ranking, attack path VẪN là path bất thường nhất — chỉ khi thực hiện bước Doc2Vec+LOF tiếp theo, các path benign được chèn vào mới có tác dụng: chúng cung cấp nhiều "mẫu bình thường" để LOF đánh giá nhầm attack path là outlier trong tập nhỏ.

**Kết luận ProvDetector**: Gadget 3 **lý thuyết đúng** nhưng không thể xác nhận thực nghiệm do phần Doc2Vec+LOF bị closed-source. Dấu hiệu gián tiếp xác nhận: top-path length trong evasion (32 cạnh) dài hơn attack path gốc, chứng tỏ các benign path ĐÃ xuất hiện trong top-K nhưng không thay thế hoàn toàn attack path.

---

### 4.2 Pagoda

#### Cơ Chế Hoạt Động

Pagoda là hệ thống **path-based whole-graph scoring**:

**Bước 1 — Frequency Database** (`freqDBWrapper.py`):
```python
# Đếm (src, dest) pairs xuất hiện >= 2 lần trong benign training
freqDB = {(srcName, destName) for pair_count >= 2}
```

**Bước 2 — Path Extraction** (`pathsWrapper.py`):
- Enumerate **tất cả** simple paths từ root đến leaf trong provenance graph (dùng `nx.all_simple_paths`)
- Với graph ~66K cạnh: hàng triệu paths (35 giây/đồ thị)

**Bước 3 — Edge Scoring**:
```python
edge_rarity = 0 if (src, dest) in freqDB else 1
path_anomaly = count_rare_edges / path_length
```

**Bước 4 — Graph Scoring**:
```python
graph_score = weighted_sum(path_anomalies, weights=path_lengths/max_path_length)
```

**Bước 5 — Thresholding** (`thresholdWrapper.py`):
```python
path_threshold = max(benign_path_scores) + 0.0001
graph_threshold = max(benign_graph_scores) + 0.0001
```

#### Kết Quả và Phân Tích Nguyên Nhân

**Sự phụ thuộc vào kích thước training set là nguyên nhân cốt lõi:**

| Training | Freq DB pairs | Threshold | Evasion score | Kết quả |
|----------|--------------|-----------|---------------|---------|
| 3 graphs | 2,583 | 0.1038 | 0.4459 | THẤT BẠI |
| 20 graphs | ~8,000 | 0.1088 | 0.4446 | THẤT BẠI |
| **71 graphs (paper)** | ~20,000+ | ~0.104 | **< 0.104** | **THÀNH CÔNG** |

**Tại sao 3/20 graphs thất bại?**

Frequency database với 3–20 đồ thị chỉ bao phủ một phần nhỏ không gian (src, dest) pairs. Khi `insertAttackPath.py` chèn các cạnh benign từ frequency DB (được xây dựng từ 71 đồ thị), nhiều cạnh benign đó KHÔNG có trong frequency DB nhỏ hơn → chúng vẫn bị đánh là "hiếm" → evasion score vẫn cao.

**Tại sao 71 graphs thành công (theo paper)?**

Với 71 đồ thị benign, frequency DB bao phủ ~20,000+ pairs. Các cạnh benign được chèn vào (từ cùng tập 71 đồ thị) được nhận diện là "thường xuyên" → rarity = 0 → graph score giảm.

**Vấn đề runtime**:
Pagoda dùng `nx.all_simple_paths()` — thuật toán có độ phức tạp **exponential** với số lượng node/cạnh. Với evasion graph ~121K cạnh (so với ~66K của benign), runtime tăng theo cấp số nhân. Đây là lý do không thể chạy full 71-graph experiment (ước tính ~3 giờ).

**Observation quan trọng**: Attack score (0.51–0.57) vs Evasion score (0.44) — evasion graph đã có score thấp hơn attack, nhưng vẫn chưa đủ thấp để qua threshold (~0.10). Điều này xác nhận cơ chế Gadget 1/2 ĐANG hoạt động, chỉ cần đủ training data.

---

### 4.3 FGA (Full Graph Autoencoder)

#### Cơ Chế Hoạt Động

FGA dùng **ARGVA** (Adversarially Regularized Variational Graph AutoEncoder):

**Kiến trúc** (`autoencoder.py`):
```
Input Graph → 2-layer GCN Encoder → [μ, log σ] (32-dim latent)
                                   ↓
                           Reparameterization trick
                                   ↓
                    Decoder (reconstruct adjacency)
                    + Discriminator (MLP 3-layer, adversarial)
```

**Node features**:
```python
Process node: [1, 0, 0]   # one-hot type 1
File node:    [0, 0, 1]   # one-hot type 3 (index 3, 0-padded)
Socket node:  [0, 1, 0]   # one-hot type 2
```

**Training** (2000 epochs):
- Encoder loss = reconstruction loss + KL divergence
- Discriminator loss = binary cross-entropy (real vs fake latent)
- Alternating optimization: encoder (lr=5e-5), discriminator (lr=1e-5)

**Inference**:
```python
# Anomaly score = minimum distance to any training embedding
scores = torch.cdist(test_embeddings, train_embeddings)
anomaly = scores.min(dim=1).values
```

#### Kết Quả và Phân Tích Nguyên Nhân

**All 5 test graphs: anomaly score 0.002–0.010 << threshold 0.021 → 100% evasion**

```
Within-training distances:  [0.0072, 0.0214, 0.0214, 0.0072]
Test graph distances:       [0.0052, 0.0099, 0.0020, 0.0024, 0.0029]
                             ↑ ALL below max training distance
```

**Tại sao FGA dễ bị qua mặt?**

1. **GCN aggregates neighborhood information**: Node embedding = f(node features, neighbor features). Khi evasion graph chứa phần lớn là benign nodes (từ benign substructures), GCN "nhìn thấy" predominantly benign neighborhoods → tạo ra embedding giống benign.

2. **Graph-level embedding = average of node embeddings**: Khi số node benign >> số node attack, graph embedding bị kéo về phía trung tâm cụm benign.

3. **ARGVA khuyến khích embedding follow prior distribution (Gaussian)**: Cả benign và evasion graph đều được map vào cùng prior → khoảng cách giữa chúng nhỏ.

**Hạn chế của run này**: Chỉ dùng 4 training + 5 test graphs (thay vì 600 + 100 như trong paper). Kết quả nhất quán với paper nhưng không thể tổng quát hóa hoàn toàn.

**Embedding norm analysis**:
```
Training norm range: [1.537, 1.587]
Test norm range:     [1.535, 1.564]
```
Các norms gần như giống hệt nhau, chứng tỏ model không thể phân biệt training và test trong không gian latent — evasion thành công hoàn toàn.

---

## 5. Phân Tích Nguyên Nhân Kết Quả

### 5.1 Nguyên Nhân Gốc Rễ: Closed-World Assumption

Tất cả ba detector đều dựa trên **closed-world assumption**: hành vi độc hại sẽ KHÁC hành vi benign. Tấn công mimicry phá vỡ giả thuyết này bằng cách làm cho attack trông giống benign.

**Vấn đề cơ bản**:
```
Mọi feature f được dùng để phân biệt attack ↔ benign
→ Kẻ tấn công có thể thêm dữ liệu để làm f(evasion) ≈ f(benign)
→ Không có feature nào "immune" với manipulation nếu kẻ tấn công biết feature đó
```

### 5.2 Nguyên Nhân Cụ Thể Cho Từng Hệ Thống

| Hệ thống | Điểm Yếu Khai Thác | Gadget |
|----------|-------------------|--------|
| ProvDetector | K-path ranking là window cố định: thêm đủ nhiều benign paths để đẩy attack path ra | 3 |
| Pagoda | Edge rarity là binary (rare/not-rare): thêm đủ nhiều "not-rare" edges để pha loãng tỷ lệ | 1 |
| FGA | Graph embedding là aggregation: thêm đủ nhiều benign nodes để kéo aggregate về benign cluster | 2 |

### 5.3 Tại Sao Kích Thước Training Set Quan Trọng Với Pagoda

```
Benign coverage = |freqDB(n)| / |total_possible_pairs|
```
- n=3:  coverage thấp → nhiều benign edges được chèn vào vẫn bị đánh là "rare"
- n=71: coverage cao → gần như tất cả benign edges được chèn đều được nhận diện đúng

Đây là vòng tròn khai thác: kẻ tấn công dùng CHÍNH frequency DB của detector để chọn edges để chèn vào. Khi training set lớn hơn, cả attacker lẫn detector đều biết nhiều hơn.

### 5.4 Asymmetry: Tại Sao Kẻ Tấn Công Có Lợi Thế

**Defender phải phát hiện TẤT CẢ attacks**; **Attacker chỉ cần tìm MỘT evasion**.

Thêm vào đó:
- Kẻ tấn công có thể **biết detector** (white-box attack trong paper)
- Kẻ tấn công có thể **thêm vô hạn benign edges** (overhead chấp nhận được với ~9K-80K cạnh thêm)
- Detector không thể phân biệt "legitimate high activity" vs "injected benign activity"

---

## 6. Điểm Yếu Chung Của Các Hệ Thống

### 6.1 Thiếu Tính Invariance với Camouflage

Không hệ thống nào có cơ chế nhận dạng "attack core" độc lập với benign context. Chúng đều tính điểm cho **toàn bộ đồ thị**, dẫn đến khả năng bị pha loãng.

### 6.2 Linear Aggregation

- Pagoda: `graph_score = Σ(weighted path scores)` — tuyến tính
- FGA: `graph_embed = avg(node_embeds)` — tuyến tính

Cả hai đều có thể bị pha loãng bằng cách thêm nhiều thành phần có score thấp.

### 6.3 Không Xem Xét Tính Semantic của Graph

Không detector nào kiểm tra:
- **Tính nhất quán temporal**: Evasion graph có thể có timestamps bất thường
- **Tính nhất quán causal**: Provenance causality chain có thể bị phá vỡ
- **Process behavior semantics**: Firefox không nên tạo binary mới và chạy chúng

### 6.4 Threshold Sensitivity

Pagoda dùng `max(benign_scores) + 0.0001` — rất tight threshold. Trong thực tế, sự biến động tự nhiên của hành vi benign (benign graphs từ các user/environment khác nhau) sẽ làm threshold cao hơn, tạo thêm buffer cho evasion.

---

## 7. Hướng Tiếp Cận Tương Lai

### 7.1 Hướng Phòng Thủ (Defense Improvements)

#### 7.1.1 Attack Core Isolation

Thay vì score toàn bộ đồ thị, tập trung vào **subgraph anomaly detection**:
```
Không dùng: score(G) = f(all_edges(G))
Thay bằng:  score(G) = max(score(s) for s ∈ subgraphs(G, size=k))
```

Phát hiện **khu vực cục bộ bất thường nhất** — không thể pha loãng bằng cách thêm benign nodes ở nơi khác.

#### 7.1.2 Causal Consistency Checking

Kiểm tra tính nhất quán nguyên nhân-kết quả:
- Một tiến trình mới chỉ có thể được tạo bởi tiến trình cha
- Data flow phải theo chiều nhất quán
- Chỉ có thể access file sau khi đã `open()` file đó

#### 7.1.3 Behavioral Signature at Process Level

Thay vì phân tích graph-level, phân tích **per-process behavior**:
```python
# Thay vì: is_anomalous(graph)?
# Dùng: for each process p: is_anomalous(behavior(p))?
```

Behavior của một tiến trình cụ thể (ví dụ Firefox) không thể bị pha loãng bằng behavior của các tiến trình khác.

#### 7.1.4 Temporal Anomaly Detection

Kiểm tra **inter-arrival time** giữa các events:
```python
# insertAttackPath.py dùng inter = 40255518 — khoảng cách cố định
# Đây là fingerprint có thể phát hiện được
```

Kẻ tấn công phải căn chỉnh timestamps, tạo ra các pattern bất thường trong phân phối thời gian.

#### 7.1.5 Ensemble Detection with Diverse Features

Dùng nhiều feature độc lập:
```
score_final = AND(score_graph, score_process, score_temporal, score_syscall_seq)
```

Để evasion thành công, kẻ tấn công phải qua mặt TẤT CẢ detectors đồng thời.

#### 7.1.6 Robust Aggregation

Thay thế average aggregation bằng các aggregation robust với outliers:
```python
# Thay vì: graph_score = mean(scores)
# Dùng:   graph_score = max(scores)  # hoặc percentile 95
#                                    # không thể pha loãng bằng addition
```

### 7.2 Hướng Nghiên Cứu Tiếp Theo

#### 7.2.1 Grey-box và Black-box Attack Evaluation

Paper hiện tại là **white-box** (attacker biết detector hoàn toàn). Cần đánh giá:
- **Grey-box**: Attacker biết loại detector nhưng không biết parameters
- **Black-box**: Attacker chỉ quan sát output (detected/not-detected)

#### 7.2.2 Adaptive Defense

Nghiên cứu **detector-aware training**: Train detector với evasion graphs để tạo adversarial robustness, tương tự adversarial training trong image classification.

#### 7.2.3 Graph Watermarking

Nhúng **watermark** vào benign training data để phát hiện khi attacker sao chép benign substructures. Nếu evasion graph chứa watermarked substructures → automatically flagged.

#### 7.2.4 Information-theoretic Lower Bounds

Nghiên cứu **lý thuyết**: Có tồn tại lower bound cho overhead của evasion không? Tức là: với bất kỳ detector nào, evasion graph phải thêm ít nhất X cạnh?

Nếu có, đây là metric để đánh giá "strength" của detector: detector tốt hơn = attacker phải thêm nhiều cạnh hơn → overhead lớn hơn → dễ phát hiện bằng các heuristic đơn giản (đồ thị quá lớn so với bình thường).

#### 7.2.5 Cross-Dataset Generalization

Hiện tại các evasion graphs được tạo **riêng cho từng dataset** (StreamSpot vs DARPA Theia). Cần nghiên cứu:
- Evasion graph được tạo cho một dataset có transfer sang dataset khác không?
- Detector được train trên một dataset có defend được attack từ dataset khác không?

#### 7.2.6 Runtime Scalability của Pagoda

`nx.all_simple_paths()` là bottleneck nghiêm trọng (exponential). Cần:
- **Sampling-based path scoring**: Thay vì enumerate tất cả paths, sample K paths ngẫu nhiên
- **Approximate algorithms**: Dùng random walks thay vì exact simple paths
- **Graph compression**: Merge nodes với behavior tương tự trước khi scoring

### 7.3 Công Cụ và Infrastructure

#### 7.3.1 Hoàn Thiện ProvDetector Pipeline

Implement open-source phần Doc2Vec + LOF:
```python
# Hiện tại chỉ có:
top_k_paths → regularity_score

# Cần thêm:
top_k_paths → doc2vec_embedding → LOF_score → classification
```

#### 7.3.2 Full-Scale Pagoda Experiment

Optimize runtime để chạy được full 71 benign + 100 attack + 100 evasion:
- Sử dụng multiprocessing để parallelize per-graph computation
- Implement path sampling thay vì exhaustive enumeration
- Estimate: từ ~3 giờ xuống ~30 phút với parallelization

#### 7.3.3 FGA với Full Training Set

Hiện tại chỉ dùng 4 training + 5 test. Cần chạy với:
- Full 71 benign training graphs
- Full 100 attack + 100 evasion test graphs
- Proper train/test split với cross-validation

---

## 8. Kết Luận

### 8.1 Tóm Tắt Kết Quả

| Hệ thống | Phát hiện attack | Evasion thành công | Gadget |
|----------|-----------------|-------------------|--------|
| ProvDetector | **100%** | Chưa xác nhận (cần Doc2Vec+LOF) | Gadget 3 |
| Pagoda (3 benign) | **100%** | **0%** (evasion thất bại) | Gadget 1+2 |
| Pagoda (20 benign) | **100%** | **0%** (evasion thất bại) | Gadget 1+2 |
| Pagoda (71 benign, paper) | — | **100%** (theo paper) | Gadget 1+2 |
| FGA (small scale) | — | **100%** (5/5) | Gadget 2 |

### 8.2 Bài Học Quan Trọng

1. **Frequency-based detectors bị pha loãng**: Bất kỳ detector nào dùng frequency/rarity của edges để scoring đều có thể bị qua mặt bằng cách thêm nhiều frequent edges.

2. **Embedding-based detectors bị kéo về cluster**: GCN và các graph neural networks dùng neighborhood aggregation đều dễ bị tấn công bằng cách thêm nhiều benign neighbors.

3. **Training set size tạo ra false sense of security**: Pagoda với ít training data cho cảm giác "an toàn" (evasion thất bại) nhưng thực ra là do frequency DB chưa đủ lớn để attacker khai thác.

4. **Attack signal không thể bị xóa hoàn toàn**: ProvDetector vẫn tìm thấy attack path với score −483.77 ngay cả trong evasion graph. Câu hỏi là liệu có thể phân loại nó đúng không — không phải detection mà là classification.

5. **Overhead là signal**: Evasion graphs có kích thước 20–1400× lớn hơn attack gốc. Đây là overhead có thể phát hiện được bằng các heuristic đơn giản.

### 8.3 Hàm Ý Thực Tiễn

Các IDS dựa trên provenance graph trong thực tế cần:
- **Defense in depth**: Không chỉ dựa vào một loại detector
- **Anomaly of anomaly**: Phát hiện đồ thị có kích thước bất thường lớn so với baseline
- **Process-level isolation**: Không để benign activity từ tiến trình khác ảnh hưởng đến score của tiến trình đáng ngờ
- **Temporal analysis**: Kiểm tra patterns trong timestamps và inter-arrival times

---

*Báo cáo này phân tích dựa trên source code tại `/home/loinguyen/agrios/mimicry-provenance-generator` và kết quả thực nghiệm trong `RESULTS_REPORT.md`.*
