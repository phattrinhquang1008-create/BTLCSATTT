<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Authentication Bypass Lab</title>
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
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 550px;
            margin: 3rem auto;
            padding: 2rem;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }
        h2 { margin-top: 0; color: #fff; }
        .form-group {
            margin-bottom: 1.2rem;
        }
        label {
            display: block;
            margin-bottom: 0.4rem;
            font-weight: 500;
        }
        input[type="text"], input[type="password"], select {
            width: 100%;
            padding: 0.6rem;
            background-color: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: #fff;
            box-sizing: border-box;
            font-size: 1rem;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: var(--accent-color);
            outline: none;
        }
        .btn {
            background-color: #238636;
            color: white;
            padding: 0.7rem 1.5rem;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
            width: 100%;
            font-weight: 600;
        }
        .btn:hover { background-color: #2ea043; }
        .alert-danger {
            background-color: rgba(248, 81, 73, 0.15);
            border: 1px solid var(--danger-color);
            color: #ff7b72;
            padding: 0.8rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }
        .alert-info {
            background-color: rgba(56, 139, 253, 0.15);
            border: 1px solid var(--accent-color);
            color: #79c0ff;
            padding: 0.8rem;
            border-radius: 6px;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }
        .cheat-box {
            margin-top: 1.5rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
            font-size: 0.85rem;
        }
        .quick-payload {
            display: inline-block;
            background: #21262d;
            border: 1px solid #30363d;
            color: #58a6ff;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            cursor: pointer;
            margin: 0.2rem;
            font-family: monospace;
        }
        .quick-payload:hover { background: #30363d; }
    </style>
</head>
<body>

<div class="container">
    <a href="index.jsp" style="color: var(--accent-color); text-decoration: none; font-size: 0.9rem;">&larr; Quay lại trang chủ</a>
    <h2>🔑 Đăng nhập hệ thống</h2>

    <% if (request.getAttribute("errorMessage") != null) { %>
        <div class="alert-danger">
            <%= request.getAttribute("errorMessage") %>
        </div>
    <% } %>

    <% if (request.getAttribute("sqlError") != null) { %>
        <div class="alert-danger">
            <strong>SQL Error:</strong> <code><%= request.getAttribute("sqlError") %></code>
        </div>
    <% } %>

    <form action="login" method="post">
        <div class="form-group">
            <label for="username">Tên người dùng (Username):</label>
            <input type="text" id="username" name="username" value="<%= request.getAttribute("usernameInput") != null ? request.getAttribute("usernameInput") : "" %>" required>
        </div>

        <div class="form-group">
            <label for="password">Mật khẩu (Password):</label>
            <input type="password" id="password" name="password">
        </div>

        <div class="form-group">
            <label for="mode">Chế độ kiểm thử (Security Mode):</label>
            <select id="mode" name="mode">
                <option value="vulnerable" selected>⚠️ Vulnerable (Statement raw string concatenation)</option>
                <option value="secure">🛡️ Secure (PreparedStatement Parameterized)</option>
            </select>
        </div>

        <button type="submit" class="btn">Đăng nhập</button>
    </form>

    <div class="cheat-box">
        <h4>⚡ Gợi ý Payload khai thác Authentication Bypass:</h4>
        <p>Bấm vào payload để điền tự động vào ô Username:</p>
        <span class="quick-payload" onclick="setPayload('admin\' -- ')">admin' -- </span>
        <span class="quick-payload" onclick="setPayload('\' OR \'1\'=\'1\' -- ')">' OR '1'='1' -- </span>
        <span class="quick-payload" onclick="setPayload('admin\' #')">admin' #</span>
        <span class="quick-payload" onclick="setPayload('\' OR 1=1 LIMIT 1; -- ')">' OR 1=1 LIMIT 1; -- </span>
    </div>
</div>

<script>
    function setPayload(val) {
        document.getElementById('username').value = val;
        document.getElementById('password').value = 'dummy_pass';
    }
</script>

</body>
</html>
