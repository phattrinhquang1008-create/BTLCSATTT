package com.sqli.lab.controller;

import com.sqli.lab.dao.UserDAO;
import com.sqli.lab.model.User;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.SQLException;

/**
 * Controller handling user authentication.
 * Demonstrates Authentication Bypass via SQL Injection.
 */
public class LoginServlet extends HttpServlet {

    private final UserDAO userDAO = new UserDAO();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String action = req.getParameter("action");
        if ("logout".equalsIgnoreCase(action)) {
            HttpSession session = req.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            resp.sendRedirect(req.getContextPath() + "/login.jsp?msg=logged_out");
            return;
        }
        req.getRequestDispatcher("/login.jsp").forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");

        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String mode = req.getParameter("mode"); // "vulnerable" (default) or "secure"

        if (username == null) username = "";
        if (password == null) password = "";

        try {
            User user;
            boolean isSecureMode = "secure".equalsIgnoreCase(mode);

            if (isSecureMode) {
                user = userDAO.loginSafe(username, password);
            } else {
                user = userDAO.login(username, password);
            }

            if (user != null) {
                HttpSession session = req.getSession();
                session.setAttribute("currentUser", user);
                session.setAttribute("authMode", isSecureMode ? "SECURE (PreparedStatement)" : "VULNERABLE (Raw Statement)");
                resp.sendRedirect(req.getContextPath() + "/index.jsp");
            } else {
                req.setAttribute("errorMessage", "Invalid credentials! Check your username or password.");
                req.setAttribute("usernameInput", username);
                req.getRequestDispatcher("/login.jsp").forward(req, resp);
            }
        } catch (SQLException e) {
            // Leak database error details (useful for demonstration & Error-based testing)
            req.setAttribute("sqlError", e.getMessage());
            req.setAttribute("usernameInput", username);
            req.getRequestDispatcher("/login.jsp").forward(req, resp);
        }
    }
}
