package com.sqli.lab.controller;

import com.sqli.lab.dao.ProductDAO;
import com.sqli.lab.model.Product;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;

/**
 * Controller handling product search.
 * Demonstrates Union-based, Error-based, and Blind SQL Injection.
 */
public class SearchServlet extends HttpServlet {

    private final ProductDAO productDAO = new ProductDAO();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        processSearch(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        processSearch(req, resp);
    }

    private void processSearch(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");

        String keyword = req.getParameter("keyword");
        String category = req.getParameter("category");
        String mode = req.getParameter("mode"); // "vulnerable" (default) or "secure"

        boolean isSecureMode = "secure".equalsIgnoreCase(mode);
        long startTime = System.currentTimeMillis();

        try {
            List<Product> products;
            if (isSecureMode) {
                products = productDAO.searchProductsSafe(keyword, category);
            } else {
                products = productDAO.searchProducts(keyword, category);
            }

            long executionTimeMs = System.currentTimeMillis() - startTime;

            req.setAttribute("products", products);
            req.setAttribute("keyword", keyword);
            req.setAttribute("category", category);
            req.setAttribute("mode", isSecureMode ? "SECURE" : "VULNERABLE");
            req.setAttribute("executionTimeMs", executionTimeMs);

            req.getRequestDispatcher("/result.jsp").forward(req, resp);

        } catch (SQLException e) {
            long executionTimeMs = System.currentTimeMillis() - startTime;
            // Verbose error output allows Error-based SQL injection exploitation
            req.setAttribute("sqlError", e.getMessage());
            req.setAttribute("keyword", keyword);
            req.setAttribute("category", category);
            req.setAttribute("mode", isSecureMode ? "SECURE" : "VULNERABLE");
            req.setAttribute("executionTimeMs", executionTimeMs);

            req.getRequestDispatcher("/result.jsp").forward(req, resp);
        }
    }
}
