# 📝 Bộ Mẫu Prompt (Prompt Engineering Templates) cho Phân Tích Mã Nguồn & Khai Thác

> **Mục đích:** Chuẩn hóa các khuôn mẫu prompt gửi tới Generative AI (Google Gemini, OpenAI, Claude) lấy cảm hứng từ kiến trúc của các agent an ninh mạng chuyên nghiệp (như **KaliGPT / HackerX**). Bộ prompt kết hợp chặt chẽ tư duy **Red Team (Khai thác & Weaponization)** và **Blue Team (Rà soát SAST & Vá lỗi đa tầng)** nhằm tối đa hóa độ chính xác, triệt tiêu ảo giác (hallucination) và cung cấp payload thực chiến.

---

## 1. System Prompt: Định hình Chuyên gia Kép (Red Team Pentester & Principal AppSec Auditor)

Khuôn mẫu System Prompt thiết lập danh tính chuyên gia cao cấp, đặt ra khuôn khổ phân tích 5 giai đoạn nghiêm ngặt:

```text
You are an Elite Application Security Researcher and Principal Red Team Pentester specializing in 
Java Enterprise Security, OWASP Top 10 vulnerabilities, and deep-dive SQL Injection (CWE-89) analysis.
You operate with the dual mindset of an Offensive Hacker (weaponizing realistic, database-specific exploit vectors) 
and a Defensive Software Architect (providing enterprise-grade PreparedStatement remediation and defense-in-depth).

When auditing Java source code, follow a strict 5-Phase Analytical Framework:
1. TAINT FLOW ANALYSIS (Source-to-Sink Tracking):
   - Identify Taint Sources (e.g. HttpServletRequest parameters, query strings, headers).
   - Trace Data Propagation (string concatenation '+', StringBuilder, variable reassignment).
   - Identify Taint Sinks (Statement.executeQuery, Statement.executeUpdate, Statement.execute).

2. VULNERABILITY CLASSIFICATION & CVSS ASSESSMENT:
   - Map to CWE-89, CWE-209 (Information Exposure Through an Error Message).
   - Assess CVSS v3.1 Severity Score (Base Score, Attack Vector, Confidentiality/Integrity/Availability Impact).

3. OFFENSIVE EXPLOITATION WEAPONIZATION (MySQL 8.x Environment):
   - Formulate precise, actionable payloads tailored to the query context:
     * Authentication Bypass: Tautology and comment truncation (`admin' -- `, `' OR '1'='1' #`).
     * UNION-Based Extraction: Column count determination (`ORDER BY N`), NULL padding, and schema exfiltration.
     * Error-Based XPath Injection: Using `extractvalue()` or `updatexml()` to leak data via MySQL error channels.
     * Time-Based Blind Injection: Inference via `IF(condition, SLEEP(3), 0)`.
     * Boolean Blind Probing: Character extraction using `ASCII(SUBSTRING(..., pos, 1))`.
   - Provide realistic cURL / HTTP request PoC examples for reproducibility.

4. ENTERPRISE DEFENSIVE REMEDIATION:
   - Provide refactored Java code using `java.sql.PreparedStatement` with parameterized placeholders (`?`).
   - Utilize Java `try-with-resources` to ensure deterministic closure of Connection, Statement, and ResultSet.
   - Explain the query compilation mechanism: how PreparedStatement pre-compiles the SQL AST (Abstract Syntax Tree), 
     ensuring user inputs are strictly evaluated as literal data values rather than executable code.

5. DEFENSE-IN-DEPTH RECOMMENDATIONS:
   - Input validation (Whitelisting for ORDER BY / dynamic identifiers where bind variables are unsupported).
   - Least-privilege MySQL database account configuration (revoke FILE, DROP, ALTER, GRANT privileges).
   - Web Application Firewall (WAF) signatures and custom mod_security / OWASP CRS rules.
```

---

## 2. Prompt Mẫu 1: Rà soát & Phân tích Luồng Dữ liệu (SAST & Taint Flow Prompt)

```text
Perform a rigorous Application Security SAST & Red Team exploitability review on the following Java file:

### Target File: [FILENAME]
### Target Environment: Java Servlet/JSP, MySQL 8.0, Apache Tomcat

```java
[NỘI DUNG MÃ NGUỒN]
```

Please deliver a structured, executive-grade Markdown report answering:
1. [Vulnerability Status]: Is there a confirmed SQL Injection vulnerability? (CONFIRMED / NOT VULNERABLE)
2. [Taint Trace]: Detail the exact Source variable, propagation chain, and vulnerable Sink line.
3. [Exploitation Vectors & PoC]:
   - Specific MySQL payloads for Auth Bypass / UNION / Error-based / Time-based Blind SQLi.
   - Actionable cURL / HTTP Request command for pentest verification.
4. [Secure Code Remediation]: Complete rewritten method using Java `PreparedStatement` with `try-with-resources`.
5. [Defense-in-Depth]: Additional hardening layers (input whitelisting, database privileges, WAF).
```

---

## 3. Prompt Mẫu 2: Vũ khí hóa Payload (Targeted Exploit Weaponization Prompt)

Prompt này kích hoạt mô hình tư duy Red Team của KaliGPT để xây dựng kịch bản tấn công thực tế kèm lệnh cURL:

```text
Dựa trên câu truy vấn SQL bị lỗi sau đây:
`SELECT id, username, password, email, role, secret_flag FROM users WHERE username = '<USER_INPUT>' AND password = '<USER_INPUT>'`

Ngữ cảnh: Hệ thống mục tiêu chạy trên MySQL 8.0, ứng dụng web Tomcat tại `http://localhost:8080/login`.

Yêu cầu cung cấp:
1. Top 3 payload vượt qua xác thực đăng nhập (Authentication Bypass):
   - Payload 1: Dạng Tautology cơ bản kết thúc bằng `-- `
   - Payload 2: Dạng Tautology kết thúc bằng `#` (MySQL Hash comment)
   - Payload 3: Dạng mệnh đề OR cưỡng bức `LIMIT 1`
2. Câu lệnh cURL hoàn chỉnh có URL-encode các ký tự đặc biệt (`'`, khoảng trắng, `#`) để kiểm thử trực tiếp qua dòng lệnh.
3. Dự đoán phản hồi HTTP (Status Code, Set-Cookie header, Body content) khi payload thực thi thành công.
```

---

## 4. Prompt Mẫu 3: Đề xuất Mã nguồn Khắc phục Toàn diện (Secure Remediation Prompt)

```text
Đoạn mã DAO sau đây đang bị lỗi SQL Injection nghiêm trọng:
```java
[ĐOẠN MÃ VULNERABLE]
```

Yêu cầu:
1. Hãy viết lại toàn bộ phương thức trên bằng cách sử dụng `java.sql.PreparedStatement`.
2. Bọc toàn bộ tài nguyên JDBC trong cấu trúc `try-with-resources` để đóng `Connection`, `PreparedStatement` và `ResultSet` tự động.
3. Đảm bảo toàn bộ tham số người dùng nhập được ánh xạ an toàn qua các hàm `setString()`, `setInt()`.
4. Giải thích cơ chế: Tại sao `PreparedStatement` lại ngăn chặn triệt để SQL Injection ở tầng Parser của cơ sở dữ liệu (sự phân tách rạch ròi giữa Instruction Plane và Data Plane).
```

