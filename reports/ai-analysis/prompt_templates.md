# 📝 Bộ Mẫu Prompt (Prompt Engineering Templates) cho Phân Tích Mã Nguồn

> **Mục đích:** Chuẩn hóa các khuôn mẫu prompt gửi tới Generative AI (Gemini, GPT-4) để đạt hiệu suất cao nhất trong việc phát hiện lỗ hổng bảo mật, giảm thiểu ảo giác (hallucination) và sinh payload khai thác chính xác.

---

## 1. System Prompt: Định hình Chuyên gia Bảo mật (Security Auditor Persona)

```text
Bạn là một Chuyên gia Cao cấp về An Toàn Thông Tin và Rà soát Mã nguồn Ứng dụng (Senior Application Security Auditor). 
Nhiệm vụ của bạn là kiểm tra mã nguồn Java Enterprise, tập trung đặc biệt vào các lỗ hổng OWASP Top 10, CWE-89 (SQL Injection).

Khi phân tích một đoạn mã nguồn, bạn PHẢI tuân thủ nghiêm ngặt phương pháp Phân tích luồng dữ liệu (Taint Flow Analysis):
1. Nhận diện Taint Source: Nơi nhận dữ liệu đầu vào từ người dùng (HttpServletRequest, parameters, headers...).
2. Theo dõi Data Propagation: Dữ liệu được gán, truyền qua các phương thức, nối chuỗi (concatenation) như thế nào.
3. Nhận diện Taint Sink: Nơi dữ liệu đầu vào được đưa trực tiếp vào hàm thực thi SQL nguy hiểm (Statement.executeQuery, executeUpdate, v.v.).
4. Đánh giá tính khả thi (Exploitability): Xác định loại SQL Injection cụ thể (Auth Bypass, Union-based, Error-based, Blind).
5. Sinh Payload Proof-of-Concept (PoC): Các payload SQL thực tế có thể khai thác thành công.
6. Đề xuất bản vá: Viết lại đoạn mã an toàn sử dụng PreparedStatement.
```

---

## 2. Prompt Mẫu 1: Rà soát & Phát hiện Lỗ hổng (Vulnerability Detection Prompt)

```text
Hãy phân tích tệp mã nguồn Java sau đây:
Tên tệp: [FILENAME]

```java
[NỘI DUNG MÃ NGUỒN]
```

Yêu cầu trả lời theo cấu trúc sau:
- Có tồn tại lỗ hổng SQL Injection không? (CÓ / KHÔNG)
- Phân loại CWE: (Ví dụ CWE-89, CWE-209...)
- Vị trí dòng mã vi phạm: (Chỉ rõ dòng và phương thức)
- Taint Source là gì? Taint Sink là gì?
- Cơ chế gây lỗi: Giải thích ngắn gọn vì sao việc ghép chuỗi ở đây lại nguy hiểm.
```

---

## 3. Prompt Mẫu 2: Sinh Payload Khai thác Mục tiêu (Targeted Exploit Generation Prompt)

```text
Dựa trên câu truy vấn SQL bị lỗi sau đây:
`SELECT id, username, password, email, role, secret_flag FROM users WHERE username = '<USER_INPUT>' AND password = '<USER_INPUT>'`

Ngữ cảnh: Hệ thống chạy trên cơ sở dữ liệu MySQL 8.0.

Hãy đề xuất:
1. Top 3 payload vượt qua xác thực đăng nhập (Authentication Bypass) mà không cần biết mật khẩu.
2. Giải thích cơ chế luận lý logic (Tautology/Comment) mà từng payload sử dụng để bẻ gãy câu lệnh SQL.
3. Tác động kinh doanh (Business Impact) khi kẻ tấn công khai thác thành công lỗ hổng này.
```

---

## 4. Prompt Mẫu 3: Đề xuất Mã nguồn Khắc phục (Automated Remediation Prompt)

```text
Đoạn mã DAO sau đây đang bị lỗi SQL Injection nghiêm trọng:
```java
[ĐOẠN MÃ VULNERABLE]
```

Yêu cầu:
1. Hãy viết lại toàn bộ phương thức trên bằng cách sử dụng `java.sql.PreparedStatement`.
2. Đảm bảo toàn bộ tham số người dùng nhập được ánh xạ qua các hàm `setString()`, `setInt()`.
3. Áp dụng chuẩn `try-with-resources` hoặc đóng `ResultSet`, `PreparedStatement`, `Connection` an toàn để tránh rò rỉ tài nguyên (Resource Leak).
4. Giải thích tại sao `PreparedStatement` lại có thể ngăn chặn triệt để SQL Injection ở mức cơ chế trình biên dịch SQL (Query Plan Pre-compilation).
```
