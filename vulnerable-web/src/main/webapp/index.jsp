<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.sqli.lab.model.User" %>
<%
    User currentUser = (User) session.getAttribute("currentUser");
    String authMode = (String) session.getAttribute("authMode");
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SQL Injection & AI Security Lab</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --accent-color: #58a6ff;
            --danger-color: #f85149;
            --success-color: #2ea043;
            --warning-color: #d29922;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
        }
        .navbar {
            background-color: var(--card-bg);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .navbar .brand {
            font-size: 1.25rem;
            font-weight: bold;
            color: var(--accent-color);
            text-decoration: none;
        }
        .navbar .nav-links a {
            color: var(--text-primary);
            text-decoration: none;
            margin-left: 1.5rem;
            font-size: 0.95rem;
        }
        .navbar .nav-links a:hover {
            color: var(--accent-color);
        }
        .container {
            max-width: 1000px;
            margin: 2rem auto;
            padding: 0 1rem;
        }
        .hero {
            background: linear-gradient(135deg, #1f2937, #111827);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .hero h1 {
            color: #ffffff;
            margin-top: 0;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .badge-danger { background-color: rgba(248, 81, 73, 0.2); color: var(--danger-color); border: 1px solid var(--danger-color); }
        .badge-success { background-color: rgba(46, 160, 67, 0.2); color: var(--success-color); border: 1px solid var(--success-color); }
        .badge-warning { background-color: rgba(210, 153, 34, 0.2); color: var(--warning-color); border: 1px solid var(--warning-color); }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            transition: transform 0.2s, border-color 0.2s;
        }
        .card:hover {
            border-color: var(--accent-color);
            transform: translateY(-2px);
        }
        .card h3 {
            margin-top: 0;
            color: #ffffff;
        }
        .btn {
            display: inline-block;
            background-color: #238636;
            color: #ffffff;
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            border: none;
            cursor: pointer;
            margin-top: 1rem;
        }
        .btn:hover { background-color: #2ea043; }
        .btn-outline {
            background-color: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        .btn-outline:hover {
            border-color: var(--accent-color);
            color: var(--accent-color);
        }
        .user-status {
            background-color: rgba(56, 139, 253, 0.1);
            border: 1px solid var(--accent-color);
            padding: 1rem;
            border-radius: 6px;
            margin-bottom: 1.5rem;
        }
        code {
            background-color: rgba(110, 118, 129, 0.4);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.9em;
            color: #ff7b72;
        }
    </style>
</head>
<body>

<div class="navbar">
    <a href="index.jsp" class="brand">🛡️ SQL Injection & AI Lab</a>
    <div class="nav-links">
        <a href="index.jsp">Trang chủ</a>
        <a href="search.jsp">Tìm kiếm (Search Lab)</a>
        <% if (currentUser == null) { %>
            <a href="login.jsp" class="badge badge-warning">Đăng nhập</a>
        <% } else { %>
            <a href="login?action=logout" class="badge badge-danger">Đăng xuất (<%= currentUser.getUsername() %>)</a>
        <% } %>
    </div>
</div>

<div class="container">
    <% if (currentUser != null) { %>
        <div class="user-status">
            <h3 style="margin: 0 0 0.5rem 0; color: #58a6ff;">🎉 Đăng nhập thành công!</h3>
            <p style="margin: 0.2rem 0;"><strong>Tài khoản:</strong> <%= currentUser.getUsername() %> | <strong>Role:</strong> <span class="badge badge-danger"><%= currentUser.getRole() %></span></p>
            <p style="margin: 0.2rem 0;"><strong>Email:</strong> <%= currentUser.getEmail() %></p>
            <p style="margin: 0.2rem 0;"><strong>Flag bí mật:</strong> <code><%= currentUser.getSecretFlag() %></code></p>
            <p style="margin: 0.2rem 0; font-size: 0.85rem; color: #8b949e;">Cơ chế: <%= authMode %></p>
        </div>
    <% } %>

    <div class="hero">
        <span class="badge badge-danger">Vulnerable Lab Environment</span>
        <h1>Khai thác SQL Injection & Ứng dụng Generative AI</h1>
        <p>Hệ thống thử nghiệm tấn công SQL Injection và ứng dụng Generative AI (LLMs) trong việc tự động rà soát, phát hiện mã độc/lỗ hổng tĩnh (SAST), gợi ý khai thác và đề xuất biện pháp khắc phục.</p>
    </div>

    <h2>Các bài thực hành (Attack Vectors)</h2>
    <div class="grid">
        <div class="card">
            <span class="badge badge-danger">CWE-89</span>
            <h3>1. Authentication Bypass</h3>
            <p>Vượt qua cơ chế xác thực đăng nhập mà không cần biết mật khẩu hợp lệ thông qua việc bẻ gãy câu lệnh SQL logic.</p>
            <p>Payload mẫu: <code>admin' -- </code> hoặc <code>' OR '1'='1' -- </code></p>
            <a href="login.jsp" class="btn">Vào Lab Đăng Nhập &rarr;</a>
        </div>

        <div class="card">
            <span class="badge badge-danger">CWE-89</span>
            <h3>2. Union-based SQLi</h3>
            <p>Sử dụng toán tử <code>UNION SELECT</code> để trích xuất dữ liệu nhạy cảm từ các bảng khác (bảng <code>users</code>) ra ngoài màn hình.</p>
            <p>Vector: Trường tìm kiếm từ khóa sản phẩm.</p>
            <a href="search.jsp" class="btn">Vào Lab Tìm Kiếm &rarr;</a>
        </div>

        <div class="card">
            <span class="badge badge-warning">CWE-209 / CWE-89</span>
            <h3>3. Error-based SQLi</h3>
            <p>Khai thác việc ứng dụng hiển thị chi tiết thông báo lỗi SQL (verbose error) bằng các hàm toán học/XML (<code>extractvalue</code>, <code>updatexml</code>).</p>
            <p>Mục tiêu: Đọc version máy chủ và thông tin database.</p>
            <a href="search.jsp" class="btn btn-outline">Thử nghiệm Error-based &rarr;</a>
        </div>

        <div class="card">
            <span class="badge badge-danger">CWE-89</span>
            <h3>4. Blind SQL Injection</h3>
            <p>Khai thác khi hệ thống không in dữ liệu hay lỗi ra màn hình. Sử dụng kỹ thuật <strong>Time-based</strong> (<code>SLEEP</code>) hoặc <strong>Boolean-based</strong>.</p>
            <p>Script tự động: <code>attacks/blind-sqli/blind_extractor.py</code></p>
            <a href="search.jsp" class="btn btn-outline">Thử nghiệm Blind SQLi &rarr;</a>
        </div>
    </div>
</div>

</body>
</html>
