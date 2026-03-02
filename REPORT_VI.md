# Báo cáo Nghiên cứu: Tấn công Bắt chước chống lại Hệ thống Phát hiện Xâm nhập Dựa trên Đồ thị Nguồn gốc

## Thông tin Bài báo

- **Tiêu đề**: "Sometimes, You Aren't What You Do: Mimicry Attacks against Provenance Graph Host Intrusion Detection Systems"
- **Tác giả**: Akul Goyal, Xueyuan Han, Gang Wang, Adam Bates
- **Hội nghị**: NDSS Symposium 2023 (Network and Distributed System Security)
- **Đơn vị**: Đại học Illinois tại Urbana-Champaign, Đại học Wake Forest

---

## 1. Vấn đề Nghiên cứu

Hệ thống Phát hiện Xâm nhập Dựa trên Nguồn gốc (Prov-HIDS) sử dụng **đồ thị nguồn gốc** (provenance graphs) — các đồ thị phụ thuộc nhân quả mô tả lịch sử thực thi hệ thống — để phát hiện xâm nhập. Mặc dù các hệ thống này cho thấy nhiều triển vọng, độ bền vững của chúng trước kẻ tấn công thích ứng chưa được chứng minh. Bài báo này nghiên cứu liệu **tấn công bắt chước** (mimicry attacks) có thể đánh bại các Prov-HIDS hiện đại dựa trên đồ thị hay không.

## 2. Các Khái niệm Chính

### Đồ thị Nguồn gốc (Provenance Graphs)
Đồ thị G = (V, E) trong đó các đỉnh đại diện cho thực thể hệ thống (tập tin, tiến trình, socket) và các cạnh đại diện cho sự kiện hệ thống (lời gọi hệ thống). Các đồ thị này nắm bắt mối quan hệ nhân quả giữa các hoạt động hệ thống.

### Quy trình Phân loại của Prov-HIDS
Tất cả Prov-HIDS đều tuân theo một mô hình chung:
1. **Phân rã** đồ thị thành các cấu trúc con (láng giềng, đường đi, hoặc đồ thị con)
2. **Mã hóa** các cấu trúc con thành vector nhúng có độ dài cố định
3. **So sánh** các vector nhúng với mô hình đã huấn luyện từ hành vi bình thường
4. **Phân loại** là bất thường nếu khoảng cách vượt quá ngưỡng

### Tấn công Bắt chước (Mimicry Attacks)
Kẻ tấn công chèn các hoạt động tiến trình trông giống bình thường vào đồ thị tấn công để ngụy trang đồ thị con tấn công, khiến Prov-HIDS phân loại sai đồ thị né tránh là bình thường.

## 3. Các Hệ thống Được Đánh giá

| Hệ thống | Phương pháp | Nhiệm vụ Học | Cách tiếp cận |
|----------|-------------|-------------|---------------|
| **StreamSpot** | Không giám sát | Đồ thị toàn phần dựa trên láng giềng | StreamHash nhúng + phân cụm tương đồng cosine |
| **Unicorn** | Không giám sát | Đồ thị toàn phần dựa trên láng giềng | HistoSketch + mô hình thời gian Jaccard |
| **ProvDetector** | Không giám sát | Đồ thị con dựa trên đường đi | Doc2Vec đường đi nhúng + Local Outlier Factor |
| **Pagoda** | Không giám sát | Đồ thị toàn phần dựa trên đường đi | Cơ sở dữ liệu tần suất + điểm bất thường dựa trên độ hiếm |
| **FGA** (Full Graph Autoencoder) | Không giám sát | Tự mã hóa đồ thị toàn phần | GCN encoder + mất mát tái tạo |

## 4. Các Chiến thuật Né tránh (Mimicry Gadgets)

### Gadget 1: Lạm dụng Mã hóa Đồ thị Không Trọng số
- **Mục tiêu**: StreamSpot, Pagoda
- **Phương pháp**: Thêm các lô cấu trúc con bình thường để pha loãng ý nghĩa của các cấu trúc con bất thường
- **Nguyên lý**: Mã hóa không trọng số đối xử bình đẳng với tất cả cấu trúc con; thêm đủ cấu trúc bình thường sẽ dịch chuyển vector nhúng vào vùng quyết định bình thường

### Gadget 2: Lạm dụng Mã hóa Đồ thị Phân phối
- **Mục tiêu**: Unicorn, FGA, Pagoda
- **Phương pháp**: Phân tích phân phối tần suất của các cấu trúc con bình thường và tái tạo phân phối đó trong đồ thị tấn công
- **Nguyên lý**: Khớp phân phối cấu trúc con làm cho vector nhúng của đồ thị tấn công không phân biệt được với đồ thị bình thường

### Gadget 3: Lạm dụng Mã hóa Đồ thị Giảm mẫu
- **Mục tiêu**: ProvDetector
- **Phương pháp**: Chèn các đường đi bình thường có độ đều đặn thấp để khai thác khoảng cách giữa hàm giảm mẫu và chỉ số khoảng cách
- **Nguyên lý**: ProvDetector chỉ kiểm tra K đường đi có độ đều đặn thấp nhất; chèn đường đi bình thường có độ thấp hơn đẩy các đường đi tấn công ra khỏi cửa sổ K

## 5. Kết quả Thực nghiệm

### Tập dữ liệu
| Tập dữ liệu | Số đỉnh | Số cạnh | Số đồ thị | Số tấn công |
|-------------|---------|---------|-----------|-------------|
| StreamSpot | 822,998 | 27,792,491 | 600 | 1 |
| DARPA TC3 THEIA | 3,721,210 | 46,303,154 | 25 | 4 |

### Tỷ lệ Né tránh Thành công (100% trên tất cả hệ thống)

| Hệ thống | Tập StreamSpot | Tập DARPA | Số cạnh thêm |
|----------|----------------|-----------|-------------|
| StreamSpot | 100% né tránh | 100% né tránh | 250K-300K (SS), 80K (DARPA) |
| Unicorn | 100% né tránh | 100% né tránh | 40K (SS), 80K (DARPA) |
| ProvDetector | 100% né tránh | 100% né tránh | 9K (SS), 10K (DARPA) |
| Pagoda | 100% né tránh | 100% né tránh | ~20K |
| FGA | 100% né tránh | 100% né tránh | ~80K |

### Khả năng Kết hợp Gadget (Tập DARPA)
Kết hợp Gadget 2 + Gadget 3 có thể đồng thời né tránh StreamSpot, Unicorn, và ProvDetector.

### Độ bền với Thay đổi Tham số
Né tránh vẫn hiệu quả ngay cả khi tham số của Prov-HIDS bị thay đổi so với giá trị khuyến nghị.

### Hiệu suất Thời gian Chạy
Tổng thời gian tạo đồ thị né tránh: **~1.82 giây** (so với RL-S2V cần 7 ngày và thất bại).

## 6. Kết quả Chạy Thử nghiệm Repository

Chúng tôi đã thực thi các cài đặt trong repository trên tập dữ liệu StreamSpot:

### Chạy ProvDetector
- **Dữ liệu huấn luyện**: 3 đồ thị bình thường từ StreamSpot (hoạt động duyệt web CNN)
- **Dữ liệu kiểm tra**: 1 đồ thị né tránh (ID đồ thị 200)
- **Kết quả**: Trích xuất 20 đường đi bất thường (K=20)
- **Độ dài đường đi**: Lên đến 1,284 cạnh mỗi đường
- **Điểm đều đặn**: -15,053.11 (các đường đi có mức bất thường cao được phát hiện trong đồ thị né tránh)
- Các đường đi của đồ thị né tránh bao gồm cả cạnh tấn công (ví dụ: kết nối đến IP đáng ngờ) và các cấu trúc con bình thường được chèn vào (hoạt động duyệt Firefox)

### Chạy Pagoda
- **Dữ liệu huấn luyện**: 3 đồ thị bình thường
- **Dữ liệu tấn công**: 1 đồ thị tấn công gốc
- **Dữ liệu né tránh**: 1 đồ thị né tránh
- **Kết quả**: `fpr: 0, tpr: 1, evasion: 1`
  - Tỷ lệ Dương tính Giả (FPR): 0 (không có đồ thị bình thường nào bị gắn nhãn sai)
  - Tỷ lệ Dương tính Thật (TPR): 1 (đồ thị tấn công được phát hiện đúng)
  - Né tránh: 1 (đồ thị né tránh vẫn bị phát hiện với tập huấn luyện nhỏ)
- **Ghi chú**: Với chỉ 3 đồ thị huấn luyện, né tránh bị phát hiện. Bài báo chứng minh rằng với dữ liệu huấn luyện đầy đủ (71+ đồ thị bình thường), né tránh đạt tỷ lệ thành công 100%.

### Đồ thị Né tránh Theia Được Xây dựng Sẵn

Thư mục `Theia-Evasion-Graphs/` chứa các đồ thị né tránh được tạo sẵn cho tập dữ liệu DARPA TC3 Theia (tấn công backdoor Firefox Drakon):

| Tệp | Bộ phát hiện | Số cạnh thêm vào |
|------|----------|-------------|
| `attack-6r1mil1.txt` / `streamSpotTheia.zip` | StreamSpot | ~80K (tổng 1M cạnh, graph ID 23) |
| `l9attack.txt` / `unicornTheia.zip` | Unicorn | ~80K (graph ID 11) |
| `evasion-provDetector.csv` / `provDetectorTheia.zip` | ProvDetector | ~10K cạnh được chèn |
| `attack-6r4mil1.txt` / `Theia-Evasion.zip` | StreamSpot (biến thể lớn hơn) | ~4M tổng cạnh |

Các tệp `.txt` sử dụng định dạng StreamSpot 6 cột phân cách bằng tab. Tệp `.csv` sử dụng định dạng ProvDetector 11 cột. Dữ liệu huấn luyện bình thường DARPA không được bao gồm trong repo và phải được lấy riêng.

## 7. Các Đóng góp Chính

1. **Tấn công bắt chước hiệu quả chống lại Prov-HIDS hiện đại**: Tỷ lệ né tránh 100% trên cả 5 hệ thống
2. **Xác định lỗ hổng mang tính hệ thống**: Các lựa chọn thiết kế trong phân rã đồ thị, mã hóa và so sánh tạo ra điểm yếu có thể khai thác
3. **Chứng minh tính khả thi thực tế**: Đồ thị né tránh được tạo trong dưới 2 giây; trình diễn tấn công trực tiếp thành công
4. **Vượt trội so với cách tiếp cận tổng quát**: RL-S2V (học tăng cường) thất bại sau 7 ngày; phương pháp này thành công nhất quán
5. **Benchmark mã nguồn mở**: Mã và tập dữ liệu công khai cho việc đánh giá Prov-HIDS trong tương lai

## 8. Các Biện pháp Giảm thiểu Tiềm năng (từ Thảo luận)

- Chuyển sang **phân loại đồ thị cấp thấp hơn** (đỉnh, cạnh, đồ thị con) thay vì đồ thị toàn phần
- Kết hợp **phân tích nhân quả dựa trên nguồn gốc** tận dụng các thuộc tính thời gian và nhân quả
- Phát triển **phát hiện hành vi chi tiết hơn** phù hợp với sản phẩm phát hiện điểm cuối thương mại
- Xem xét **phân tích nguyên nhân gốc và tác động** trong quy trình phân loại

## 9. Kết luận

Công trình này chứng minh rằng tấn công bắt chước vẫn là mối đe dọa cơ bản đối với phát hiện xâm nhập dựa trên nguồn gốc. Các lựa chọn thiết kế có tính hệ thống trong tất cả Prov-HIDS được đánh giá — phân rã đồ thị, vector hóa và so sánh có giới hạn — tạo ra các khoảng trống có thể khai thác cho phép kẻ tấn công chèn các cấu trúc con bình thường và né tránh phát hiện với tỷ lệ thành công 100%. Phương pháp này hiệu quả (< 2 giây), thực tế (đã được trình diễn trong tấn công trực tiếp) và có thể tổng quát hóa trên nhiều mô hình phát hiện khác nhau.

---

*Báo cáo được tạo từ bài báo NDSS 2023 và thực thi repository mimicry-provenance-generator.*
