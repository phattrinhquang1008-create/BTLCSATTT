package com.sqli.lab.dao;

import com.sqli.lab.database.DBConnection;
import com.sqli.lab.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Data Access Object for User operations.
 * Demonstrates vulnerable vs secure database query patterns.
 */
public class UserDAO {

    /**
     * [VULNERABLE METHOD]
     * Performs authentication using direct string concatenation into SQL Statement.
     * 
     * SINK: Statement.executeQuery(sql)
     * VULNERABILITY: SQL Injection (Authentication Bypass)
     * CWE: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
     * 
     * Example Exploit Payload:
     *   username: admin' -- 
     *   password: (any)
     *   resulting query: SELECT * FROM users WHERE username = 'admin' -- ' AND password = '...'
     */
    public User login(String username, String password) throws SQLException {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            conn = DBConnection.getConnection();
            stmt = conn.createStatement();

            // Direct concatenation of user-supplied inputs (Taint Source -> Sink)
            String sql = "SELECT id, username, password, email, role, secret_flag FROM users "
                       + "WHERE username = '" + username + "' AND password = '" + password + "'";

            System.out.println("[DEBUG UserDAO.login] Executing raw SQL: " + sql);
            rs = stmt.executeQuery(sql);

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
            return null;
        } finally {
            if (rs != null) try { rs.close(); } catch (Exception ignored) {}
            if (stmt != null) try { stmt.close(); } catch (Exception ignored) {}
            if (conn != null) try { conn.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * [SECURE / REMEDIATED METHOD]
     * Uses PreparedStatement with parameterized query to completely mitigate SQL Injection.
     */
    public User loginSafe(String username, String password) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = DBConnection.getConnection();
            String sql = "SELECT id, username, password, email, role, secret_flag FROM users "
                       + "WHERE username = ? AND password = ?";

            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
            pstmt.setString(2, password);

            rs = pstmt.executeQuery();
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
            return null;
        } finally {
            if (rs != null) try { rs.close(); } catch (Exception ignored) {}
            if (pstmt != null) try { pstmt.close(); } catch (Exception ignored) {}
            if (conn != null) try { conn.close(); } catch (Exception ignored) {}
        }
    }
}
