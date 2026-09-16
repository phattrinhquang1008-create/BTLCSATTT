package com.sqli.lab.dao;

import com.sqli.lab.database.DBConnection;
import com.sqli.lab.model.Product;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Data Access Object for Product catalog operations.
 * Demonstrates multiple SQL Injection vectors in search functionality:
 * - Union-based SQLi
 * - Error-based SQLi
 * - Blind SQLi (Boolean-based & Time-based)
 */
public class ProductDAO {

    /**
     * [VULNERABLE METHOD]
     * Searches products by keyword and optional category using raw SQL concatenation.
     * 
     * SINK: Statement.executeQuery(sql)
     * VULNERABILITY: SQL Injection (Union-based, Error-based, Blind)
     * CWE: CWE-89
     * 
     * Example Exploit Payloads:
     * 1. Union-based:
     *    keyword: ' UNION SELECT id, username, password, role, 0.0, 1 FROM users -- 
     * 2. Error-based (MySQL):
     *    keyword: ' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e)) -- 
     * 3. Time-based Blind:
     *    keyword: ' AND IF(1=1, SLEEP(3), 0) -- 
     */
    public List<Product> searchProducts(String keyword, String category) throws SQLException {
        List<Product> list = new ArrayList<>();
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            conn = DBConnection.getConnection();
            stmt = conn.createStatement();

            // Flawed query construction: directly interpolating user input
            String sql = "SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1";

            if (keyword != null && !keyword.trim().isEmpty()) {
                sql += " AND (name LIKE '%" + keyword + "%' OR description LIKE '%" + keyword + "%')";
            }

            if (category != null && !category.trim().isEmpty() && !"ALL".equalsIgnoreCase(category)) {
                sql += " AND category = '" + category + "'";
            }

            System.out.println("[DEBUG ProductDAO.searchProducts] Executing raw SQL: " + sql);
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                Product p = new Product(
                    rs.getInt(1),
                    rs.getString(2),
                    rs.getString(3),
                    rs.getString(4),
                    rs.getDouble(5),
                    rs.getInt(6)
                );
                list.add(p);
            }
        } finally {
            if (rs != null) try { rs.close(); } catch (Exception ignored) {}
            if (stmt != null) try { stmt.close(); } catch (Exception ignored) {}
            if (conn != null) try { conn.close(); } catch (Exception ignored) {}
        }

        return list;
    }

    /**
     * [SECURE / REMEDIATED METHOD]
     * Uses PreparedStatement to safely parameterize LIKE queries and filters.
     */
    public List<Product> searchProductsSafe(String keyword, String category) throws SQLException {
        List<Product> list = new ArrayList<>();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = DBConnection.getConnection();
            StringBuilder sql = new StringBuilder("SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1");

            boolean hasKeyword = keyword != null && !keyword.trim().isEmpty();
            boolean hasCategory = category != null && !category.trim().isEmpty() && !"ALL".equalsIgnoreCase(category);

            if (hasKeyword) {
                sql.append(" AND (name LIKE ? OR description LIKE ?)");
            }
            if (hasCategory) {
                sql.append(" AND category = ?");
            }

            pstmt = conn.prepareStatement(sql.toString());

            int paramIndex = 1;
            if (hasKeyword) {
                String pattern = "%" + keyword + "%";
                pstmt.setString(paramIndex++, pattern);
                pstmt.setString(paramIndex++, pattern);
            }
            if (hasCategory) {
                pstmt.setString(paramIndex++, category);
            }

            rs = pstmt.executeQuery();
            while (rs.next()) {
                Product p = new Product(
                    rs.getInt(1),
                    rs.getString(2),
                    rs.getString(3),
                    rs.getString(4),
                    rs.getDouble(5),
                    rs.getInt(6)
                );
                list.add(p);
            }
        } finally {
            if (rs != null) try { rs.close(); } catch (Exception ignored) {}
            if (pstmt != null) try { pstmt.close(); } catch (Exception ignored) {}
            if (conn != null) try { conn.close(); } catch (Exception ignored) {}
        }

        return list;
    }
}
