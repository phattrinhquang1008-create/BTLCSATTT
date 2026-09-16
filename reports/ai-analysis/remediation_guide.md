# 🛡️ Hướng Dẫn Khắc Phục Lỗ Hổng SQL Injection Toàn Diện (Remediation Guide)

> **Mục tiêu:** Cung cấp tài liệu kỹ thuật chuyên sâu về các biện pháp phòng thủ đa tầng (Defense-in-Depth) nhằm loại bỏ hoàn toàn nguy cơ tấn công SQL Injection trong ứng dụng Java.

---

## 1. Biện Pháp Phòng Ngự Cốt Lõi: Tham Số Hóa Truy Vấn (Parameterized Queries / PreparedStatement)

### Vì sao `PreparedStatement` ngăn chặn được SQL Injection?
Khi sử dụng `java.sql.Statement` thông thường, chuỗi SQL và dữ liệu người dùng được ghép nối với nhau thành một chuỗi duy nhất trước khi gửi tới cơ sở dữ liệu. Trình biên dịch SQL (SQL Parser) sẽ phân tích cú pháp toàn bộ chuỗi đó, khiến các ký tự đặc biệt như `'`, `--`, `UNION`, `OR` trong input của người dùng bị hiểu nhầm thành các lệnh điều khiển SQL.

Khi sử dụng `java.sql.PreparedStatement`:
1. **Tiền biên dịch (Pre-compilation):** Khung câu lệnh SQL với các dấu hỏi chấm `?` (placeholder) được gửi tới cơ sở dữ liệu để biên dịch và xây dựng cây phân tích cú pháp (Execution Plan) **trước**.
2. **Cách ly dữ liệu (Data-Code Separation):** Sau đó, các giá trị do người dùng nhập vào mới được gửi qua mạng dưới dạng các tham số dữ liệu thuần túy (data literals).
3. Cho dù người dùng có nhập chuỗi `' OR '1'='1' -- ` thì cơ sở dữ liệu vẫn chỉ coi toàn bộ chuỗi đó là một giá trị chuỗi (String literal) để so khớp với cột `username`, hoàn toàn không thể làm thay đổi cấu trúc của câu lệnh SQL ban đầu.

---

## 2. Mã Nguồn Minh Họa Trước và Sau Khi Khắc Phục

### A. Đối với chức năng Xác thực Đăng nhập (`UserDAO.java`)

#### ❌ Đoạn mã DỄ BỊ TỔN THƯƠNG (Vulnerable):
```java
// Ghép chuỗi trực tiếp -> Bị Authentication Bypass
String sql = "SELECT id, username, password, email, role, secret_flag FROM users "
           + "WHERE username = '" + username + "' AND password = '" + password + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

#### ✅ Đoạn mã ĐÃ ĐƯỢC KHẮC PHỤC (Remediated):
```java
// Sử dụng PreparedStatement và khối try-with-resources an toàn
String sql = "SELECT id, username, password, email, role, secret_flag FROM users "
           + "WHERE username = ? AND password = ?";

try (Connection conn = DBConnection.getConnection();
     PreparedStatement pstmt = conn.prepareStatement(sql)) {

    pstmt.setString(1, username);
    pstmt.setString(2, password);

    try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
            return new User(
                rs.getInt("id"),
                rs.getString("username"),
                rs.getString("password"),
                rs.getString("email"),
                rs.getString("role"),
                rs.getString("secret_flag")
            );
        }
    }
}
```

---

### B. Đối với chức năng Tìm kiếm sản phẩm (`ProductDAO.java`)

#### ❌ Đoạn mã DỄ BỊ TỔN THƯƠNG (Vulnerable):
```java
// Nối chuỗi trong mệnh đề LIKE và WHERE -> Bị Union, Error, Blind SQLi
String sql = "SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1";
if (keyword != null) {
    sql += " AND (name LIKE '%" + keyword + "%' OR description LIKE '%" + keyword + "%')";
}
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

#### ✅ Đoạn mã ĐÃ ĐƯỢC KHẮC PHỤC (Remediated):
```java
StringBuilder sql = new StringBuilder("SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1");
boolean hasKeyword = keyword != null && !keyword.trim().isEmpty();
boolean hasCategory = category != null && !category.trim().isEmpty() && !"ALL".equalsIgnoreCase(category);

if (hasKeyword) {
    sql.append(" AND (name LIKE ? OR description LIKE ?)");
}
if (hasCategory) {
    sql.append(" AND category = ?");
}

try (Connection conn = DBConnection.getConnection();
     PreparedStatement pstmt = conn.prepareStatement(sql.toString())) {

    int index = 1;
    if (hasKeyword) {
        String wildcardPattern = "%" + keyword + "%";
        pstmt.setString(index++, wildcardPattern);
        pstmt.setString(index++, wildcardPattern);
    }
    if (hasCategory) {
        pstmt.setString(index++, category);
    }

    try (ResultSet rs = pstmt.executeQuery()) {
        while (rs.next()) {
            // Mapping kết quả an toàn
        }
    }
}
```

---

## 3. Các Biện Pháp Phòng Thủ Chiều Sâu (Defense-in-Depth)

Ngoài việc sử dụng `PreparedStatement`, hệ thống cần áp dụng đồng thời các nguyên tắc sau:

### 1. Nguyên Tắc Đặc Quyền Tối Thiểu (Principle of Least Privilege)
- Không bao giờ để ứng dụng web kết nối cơ sở dữ liệu bằng tài khoản `root` hoặc `sa`.
- Tạo user riêng cho ứng dụng web (ví dụ `sqli_web_app`) chỉ có quyền `SELECT`, `INSERT`, `UPDATE` trên các bảng cần thiết.
- Tước bỏ toàn bộ quyền truy cập vào `information_schema`, `mysql`, `performance_schema` và thu hồi quyền gọi các hàm nguy hiểm (`LOAD_FILE()`, `INTO OUTFILE`).

### 2. Kiểm Soát Ngoại Lệ & Vô Hiệu Hóa Verbose Error Messages
- Tuyệt đối không in `e.getMessage()` của `SQLException` ra giao diện người dùng (chống lại kỹ thuật **Error-based SQLi**).
- Luôn hiển thị trang lỗi chung thân thiện (Generic Error Page) ví dụ: *"Đã xảy ra lỗi hệ thống, vui lòng thử lại sau."* và ghi vết lỗi chi tiết vào file log nội bộ an toàn.

### 3. Kiểm Tra Hợp Lệ Dữ Liệu Đầu Vào (Input Validation & Whitelisting)
- Với các trường dữ liệu dạng danh mục hoặc sắp xếp (`ORDER BY column ASC/DESC` - nơi không thể dùng placeholder `?`), bắt buộc sử dụng **Whitelist Validation**:
  ```java
  List<String> allowedColumns = List.of("id", "name", "price");
  if (!allowedColumns.contains(sortBy)) {
      throw new IllegalArgumentException("Cột sắp xếp không hợp lệ!");
  }
  ```

### 4. Triển Khai Tường Lửa Ứng Dụng Web (Web Application Firewall - WAF)
- Trang bị WAF (như ModSecurity, Cloudflare WAF, AWS WAF) để giám sát và ngăn chặn các payload SQL Injection phổ biến ngay tại tầng biên trước khi request chạm vào máy chủ ứng dụng.
