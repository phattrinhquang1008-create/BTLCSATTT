# 🛡️ BÁO CÁO PHÂN TÍCH LỖ HỔNG MÃ NGUỒN BẰNG GENERATIVE AI

> **Học phần:** An Toàn Thông Tin
> **Đề tài:** Khai thác SQL Injection và Ứng dụng Generative AI trong phân tích lỗ hổng mã nguồn Java
> **Thời gian khởi tạo:** 2026-09-16T14:38:34.211062

## 1. TỔNG QUAN KẾT QUẢ RÀ SOÁT (EXECUTIVE SUMMARY)

| Chỉ số kiểm tra | Giá trị |
|:---|:---|
| **Thư mục mã nguồn mục tiêu** | `C:\Users\phatt\.gemini\antigravity\scratch\SQLInjection-Attack-AI\vulnerable-web\src\main\java` |
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

### AI Static Analysis Findings for `ProductDAO.java`

**1. Vulnerability Assessment:**
- **Type:** Multiple SQL Injection Vectors (Union-based, Error-based, Blind SQLi)
- **CWE:** CWE-89 / CWE-209
- **Severity:** CRITICAL (CVSS 9.8)

**2. Taint Flow:**
- **Source:** Parameters `keyword` and `category` in method `searchProducts()`.
- **Sink:** `stmt.executeQuery(sql)` with dynamically concatenated `WHERE` clauses.

**3. Concrete Exploitation Payloads:**
A. **Union-based SQLi (Data Extraction):**
   `' UNION SELECT id, username, password, email, 0.0, 1 FROM users -- `
   *Result:* Appends sensitive records from `users` table directly to product search results.

B. **Error-based SQLi (Server Leakage):**
   `' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e)) -- `
   *Result:* Forces MySQL syntax error containing database version and user credentials.

C. **Time-based Blind SQLi:**
   `' AND IF(1=1, SLEEP(3), 0) -- `
   *Result:* Induces intentional 3-second database sleep to infer boolean conditions.

**4. Secure Remediation:**
Use `PreparedStatement` with parameterized wildcards for the `LIKE` clause:
```java
String sql = "SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1 AND (name LIKE ? OR description LIKE ?)";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, "%" + keyword + "%");
pstmt.setString(2, "%" + keyword + "%");
```


---

## Phân tích tệp `UserDAO.java`

### AI Static Analysis Findings for `UserDAO.java`

**1. Vulnerability Assessment:**
- **Type:** SQL Injection (Authentication Bypass)
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Severity:** CRITICAL (CVSS 9.8)

**2. Taint Flow:**
- **Source:** Parameters `username` and `password` passed to method `login()`.
- **Sink:** `stmt.executeQuery(sql)` in `UserDAO.java`.
- **Mechanism:** Direct concatenation creates an unsanitized SQL string.

**3. Exploitation Payloads (Authentication Bypass):**
```sql
Username: admin' -- 
Username: ' OR '1'='1' -- 
Username: ' OR 1=1 LIMIT 1; -- 
```
**Impact:** An attacker can authenticate as the administrator without knowing the password, gaining full access to user management, emails, and sensitive security flags.

**4. Secure Remediation:**
Replace the raw `Statement` with `PreparedStatement` to ensure user inputs are treated strictly as data literals:
```java
String sql = "SELECT id, username, password, email, role, secret_flag FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();
```


---



## 4. KẾT LUẬN & ĐÁNH GIÁ CỦA CHUYÊN VIÊN AN TOÀN THÔNG TIN

1. **Độ chính xác:** Generative AI nhận diện chính xác 100% các điểm nối chuỗi SQL trực tiếp trong các lớp DAO.
2. **Tính khả thi của Payload:** Tất cả các payload AI sinh ra đều tương thích hoàn hảo với cú pháp của cơ sở dữ liệu MySQL.
3. **Khả năng sinh mã sửa lỗi:** Mã `PreparedStatement` do AI đề xuất đạt chuẩn kiến trúc bảo mật phòng thủ chiều sâu.
