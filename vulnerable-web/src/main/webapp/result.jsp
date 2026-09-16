<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.util.List" %>
<%@ page import="com.sqli.lab.model.Product" %>
<%
    List<Product> products = (List<Product>) request.getAttribute("products");
    String keyword = (String) request.getAttribute("keyword");
    String category = (String) request.getAttribute("category");
    String mode = (String) request.getAttribute("mode");
    String sqlError = (String) request.getAttribute("sqlError");
    Long executionTimeMs = (Long) request.getAttribute("executionTimeMs");
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Kết quả tìm kiếm - SQL Injection Lab</title>
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
            max-width: 1000px;
            margin: 2rem auto;
            padding: 2rem;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
        }
        h2 { margin: 0; color: #fff; }
        .meta-bar {
            background-color: #0d1117;
            padding: 0.8rem 1rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
        }
        .meta-bar span strong { color: #fff; }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.8rem;
        }
        .badge-danger { background-color: rgba(248, 81, 73, 0.2); color: var(--danger-color); border: 1px solid var(--danger-color); }
        .badge-success { background-color: rgba(46, 160, 67, 0.2); color: var(--success-color); border: 1px solid var(--success-color); }
        .badge-warning { background-color: rgba(210, 153, 34, 0.2); color: var(--warning-color); border: 1px solid var(--warning-color); }
        .table-responsive {
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        th, td {
            border: 1px solid var(--border-color);
            padding: 0.75rem 1rem;
            text-align: left;
        }
        th {
            background-color: #21262d;
            color: #fff;
            font-weight: 600;
        }
        tr:hover {
            background-color: rgba(110, 118, 129, 0.1);
        }
        .error-card {
            background-color: rgba(248, 81, 73, 0.1);
            border: 1px solid var(--danger-color);
            border-radius: 6px;
            padding: 1.2rem;
            margin-bottom: 1.5rem;
        }
        .error-card h3 {
            margin-top: 0;
            color: var(--danger-color);
            font-size: 1.1rem;
        }
        .error-card pre {
            background-color: #0d1117;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            color: #ff7b72;
            font-size: 0.95rem;
            border: 1px solid rgba(248, 81, 73, 0.3);
        }
        .btn-back {
            color: var(--accent-color);
            text-decoration: none;
            font-size: 0.9rem;
        }
        .time-highlight {
            color: <%= (executionTimeMs != null && executionTimeMs >= 2000) ? "#f85149" : "#58a6ff" %>;
            font-weight: bold;
        }
    </style>
</head>
<body>

<div class="container">
    <div class="header">
        <h2>📦 Kết quả tra cứu sản phẩm</h2>
        <a href="search.jsp" class="btn-back">&larr; Quay lại form tìm kiếm</a>
    </div>

    <div class="meta-bar">
        <span>Từ khóa: <strong><%= keyword != null ? keyword : "" %></strong></span>
        <span>Danh mục: <strong><%= category != null ? category : "ALL" %></strong></span>
        <span>Chế độ: <span class="badge <%= "SECURE".equals(mode) ? "badge-success" : "badge-danger" %>"><%= mode %></span></span>
        <span>Thời gian phản hồi (Latency): <span class="time-highlight"><%= executionTimeMs != null ? executionTimeMs : 0 %> ms</span></span>
    </div>

    <% if (sqlError != null) { %>
        <div class="error-card">
            <h3>💥 SQL Exception Triggered (Khai thác Error-based SQLi thành công):</h3>
            <p>Database trả về thông báo lỗi trực tiếp cho người dùng. Dữ liệu trích xuất từ payload:</p>
            <pre><%= sqlError %></pre>
        </div>
    <% } %>

    <% if (products != null && !products.isEmpty()) { %>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th style="width: 50px;">ID</th>
                        <th style="width: 200px;">Tên sản phẩm / Field 2</th>
                        <th>Mô tả / Field 3</th>
                        <th style="width: 140px;">Danh mục / Field 4</th>
                        <th style="width: 100px;">Giá ($)</th>
                        <th style="width: 80px;">Tồn kho</th>
                    </tr>
                </thead>
                <tbody>
                    <% for (Product p : products) { %>
                        <tr>
                            <td><%= p.getId() %></td>
                            <td><strong><%= p.getName() %></strong></td>
                            <td><%= p.getDescription() %></td>
                            <td><span class="badge badge-warning"><%= p.getCategory() %></span></td>
                            <td>$<%= p.getPrice() %></td>
                            <td><%= p.getInStock() %></td>
                        </tr>
                    <% } %>
                </tbody>
            </table>
        </div>
    <% } else if (sqlError == null) { %>
        <div style="text-align: center; padding: 3rem; color: #8b949e;">
            <h3>Không tìm thấy sản phẩm nào phù hợp!</h3>
            <p>Nếu bạn đang kiểm thử Boolean-based Blind SQLi, kết quả trống (0 records) đại diện cho mệnh đề logic <code>FALSE</code>.</p>
        </div>
    <% } %>
</div>

</body>
</html>
