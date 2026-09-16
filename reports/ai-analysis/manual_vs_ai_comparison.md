# ⚖️ Báo Cáo Đối Chiếu Đánh Giá: Generative AI vs Kiểm Thử Thủ Công (Manual Pentest)

> **Môn học:** An Toàn Thông Tin  
> **Chủ đề nghiên cứu:** Đánh giá năng lực của Generative AI trong việc rà soát mã nguồn tĩnh (SAST), hỗ trợ xây dựng kịch bản khai thác SQL Injection và khả năng khắc phục so với phương pháp kiểm thử thủ công truyền thống.

---

## 1. Bảng So Sánh Tổng Hợp (Comparative Matrix)

| Tiêu chí đánh giá | Công cụ SAST Truyền thống (SonarQube/Checkmarx) | Generative AI (LLMs: Gemini / GPT) | Kiểm thử Thủ công (Manual Pentest) |
|:---|:---|:---|:---|
| **Tốc độ rà soát** | Cực nhanh (vài giây cho toàn bộ repo) | Nhanh (~1-3 giây mỗi tệp mã nguồn) | Chậm (đòi hỏi nhiều giờ/ngày từ chuyên gia) |
| **Phát hiện Sink/Source** | Quy tắc Regex / AST cố định | Phân tích ngữ cảnh & hiểu luồng dữ liệu thông minh | Trực quan theo kinh nghiệm pentester |
| **Hiểu nghiệp vụ (Business Logic)** | Rất kém (thường chỉ bắt được cú pháp) | Tốt (hiểu vai trò của Controller, DAO, Auth) | Rất tốt |
| **Tỷ lệ Báo động giả (False Positive)** | Khá cao (do không hiểu context) | Thấp hơn khi có System Prompt chuẩn | Rất thấp (đã qua thực nghiệm trực tiếp) |
| **Tự động sinh Payload thực tế** | **Không hỗ trợ** (chỉ báo lỗi) | **Rất tốt** (sinh payload Auth Bypass, Union, Blind chính xác) | Xuất sắc (linh hoạt điều chỉnh theo WAF/DB) |
| **Đề xuất mã vá lỗi (Remediation)** | Hướng dẫn chung chung dạng template | **Sinh code PreparedStatement hoàn chỉnh**, cắm chạy ngay | Viết bản vá tùy biến theo kiến trúc dự án |
| **Phát hiện lỗi logic phức tạp** | Kém | Trung bình - Khá | Xuất sắc |

---

## 2. Phân Tích Chi Tiết Theo Từng Vector Tấn Công

### A. Authentication Bypass (`UserDAO.java`)
- **Generative AI:**
  - Nhận diện ngay lập tức việc nối chuỗi `username` và `password` vào `Statement.executeQuery()`.
  - Đề xuất chính xác các payload kinh điển: `admin' -- `, `' OR '1'='1' -- `.
  - Nhận định chính xác mức độ nghiêm trọng: **CRITICAL** (ảnh hưởng đến quyền quản trị cao nhất).
- **Thực nghiệm Thủ công:**
  - Nhập payload do AI đề xuất vào form `login.jsp`.
  - Kết quả: Hệ thống đăng nhập thành công ngay lần thử đầu tiên, lấy được Flag `FLAG{sqli_admin_bypass_master_2026}`.
  - **Đánh giá:** AI đạt độ chính xác 100% về tính khả thi của kịch bản khai thác.

### B. Union-based SQL Injection (`ProductDAO.java`)
- **Generative AI:**
  - Phân tích câu lệnh `SELECT id, name, description, category, price, in_stock FROM products`.
  - Chỉ ra số cột ban đầu là **6 cột**, kiểu dữ liệu tương ứng.
  - Sinh payload `UNION SELECT id, username, password, email, 0.0, id FROM users -- ` tương thích hoàn hảo về số lượng cột và kiểu dữ liệu.
- **Thực nghiệm Thủ công:**
  - Gửi request qua Burp Suite / Trình duyệt.
  - Danh sách bảng sản phẩm phản ánh chính xác dữ liệu bảng `users`.
  - **Đánh giá:** AI tiết kiệm 90% thời gian cho pentester trong bước dò số cột (thông thường phải thử `ORDER BY 1, 2, 3...` nhiều lần).

### C. Error-based & Blind SQL Injection
- **Generative AI:**
  - Nhận diện cơ sở dữ liệu là MySQL thông qua JDBC URL và thư viện `mysql-connector-j`.
  - Lựa chọn đúng các hàm đặc thù của MySQL: `extractvalue()` cho Error-based và `SLEEP()` cho Time-based.
- **Thực nghiệm Thủ công:**
  - Kiểm thử `extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e))` kích hoạt chính xác lỗi XPath trên MySQL 8.0.
  - Kiểm thử `SLEEP(3)` ghi nhận độ trễ HTTP phản hồi đúng 3.085 ms.
  - **Đánh giá:** AI hiểu rất sâu về phương ngữ SQL (SQL Dialects) của từng hệ quản trị cơ sở dữ liệu.

---

## 3. Điểm Mạnh & Hạn Chế của Generative AI trong An Toàn Thông Tin

### Điểm mạnh vượt trội:
1. **Rút ngắn thời gian Pentest:** AI đóng vai trò như một trợ lý Copilot, hỗ trợ pentester phân tích nhanh hàng nghìn dòng code và sinh sẵn các payload ứng viên.
2. **Khả năng sinh bản vá hoàn chỉnh:** Không chỉ chỉ ra lỗi, AI còn viết lại toàn bộ hàm DAO bằng `PreparedStatement` kèm cú pháp `try-with-resources` đạt chuẩn Clean Code.
3. **Thích ứng đa ngôn ngữ:** Hoạt động tốt trên Java, Python, PHP, C#, Go mà không cần cài đặt các plugin AST phức tạp.

### Hạn chế cần lưu ý:
1. **Nguy cơ Ảo giác (Hallucination):** Nếu không cung cấp đủ ngữ cảnh schema database, AI có thể đoán sai tên bảng hoặc tên cột (ví dụ đoán bảng `tbl_user` thay vì `users`).
2. **Giới hạn Context Window:** Với các dự án lớn hàng triệu dòng mã, không thể đưa toàn bộ mã nguồn vào prompt cùng một lúc. Cần kết hợp kỹ thuật chia nhỏ file (chunking) hoặc RAG (Retrieval-Augmented Generation).
3. **Phụ thuộc kết nối / API:** Cần lưu ý bảo mật dữ liệu nguồn khi gửi code độc quyền lên các dịch vụ đám mây công cộng (Cloud LLMs).

---

## 4. Kết Luận & Khuyến Nghị Kiến Trúc DevSecOps
Mô hình kết hợp tối ưu cho các doanh nghiệp và dự án phần mềm hiện đại là **Human-in-the-loop DevSecOps**:
```
Lập trình viên viết Code 
  ──> AI Analyzer quét tự động trong CI/CD Pipeline 
  ──> Sinh báo cáo & Đề xuất Payload 
  ──> Chuyên viên Pentest xác thực nhanh 
  ──> Áp dụng bản vá do AI sinh ra.
```
Mô hình này giúp tăng tốc độ phát hiện và xử lý lỗ hổng gấp 5 - 10 lần so với quy trình kiểm thử thủ công thuần túy.
