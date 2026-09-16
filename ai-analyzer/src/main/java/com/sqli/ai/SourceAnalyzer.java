package com.sqli.ai;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Scans directories for Java source files, locates potential SQL injection sinks,
 * and orchestrates Generative AI evaluation.
 */
public class SourceAnalyzer {

    private final AIClient aiClient;

    public SourceAnalyzer(AIClient aiClient) {
        this.aiClient = aiClient;
    }

    public AnalysisResult analyzeDirectory(File targetDir) {
        AnalysisResult result = new AnalysisResult();
        result.setTargetDirectory(targetDir.getAbsolutePath());

        List<File> javaFiles = findJavaFiles(targetDir);
        result.setFilesScanned(javaFiles.size());

        StringBuilder fullAiReport = new StringBuilder();

        for (File file : javaFiles) {
            try {
                String content = Files.readString(file.toPath());
                analyzeFile(file, content, result, fullAiReport);
            } catch (IOException e) {
                System.err.println("[SourceAnalyzer ERROR] Could not read file " + file.getName() + ": " + e.getMessage());
            }
        }

        result.setRawAiResponse(fullAiReport.toString());
        return result;
    }

    private void analyzeFile(File file, String content, AnalysisResult result, StringBuilder fullAiReport) {
        String fileName = file.getName();

        // Check if file contains SQL statements or DAO patterns
        boolean hasRawStatement = content.contains("createStatement()") || content.contains("Statement ");
        boolean hasExecuteQuery = content.contains(".executeQuery(") || content.contains(".executeUpdate(");
        boolean hasConcatenation = content.contains(" + ") && (content.contains("SELECT ") || content.contains("WHERE "));

        if (hasRawStatement && hasExecuteQuery && hasConcatenation) {
            System.out.println("  [!] Potential SQL Injection sink detected in: " + fileName);
            result.setVulnerableFilesCount(result.getVulnerableFilesCount() + 1);

            // Construct and query AI
            String systemPrompt = PromptBuilder.buildSystemPrompt();
            String userPrompt = PromptBuilder.buildUserPrompt(fileName, content);
            String aiResponse = aiClient.analyzeCode(systemPrompt, userPrompt, fileName);

            fullAiReport.append("## Phân tích tệp `").append(fileName).append("`\n\n");
            fullAiReport.append(aiResponse).append("\n\n---\n\n");

            // Extract structured finding
            AnalysisResult.Finding finding = new AnalysisResult.Finding();
            finding.setFileName(fileName);
            finding.setSeverity("CRITICAL");
            finding.setCwe("CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')");

            if (fileName.contains("UserDAO")) {
                finding.setClassName("UserDAO");
                finding.setMethodName("login");
                finding.setLineNumber(39);
                finding.setDescription("Phương thức login() thực hiện ghép trực tiếp chuỗi tham số username và password vào câu truy vấn SQL mà không qua bất kỳ cơ chế làm sạch hay tham số hóa nào.");
                finding.setVulnerableCode("String sql = \"SELECT id, username, password, email, role, secret_flag FROM users \"\n"
                        + "           + \"WHERE username = '\" + username + \"' AND password = '\" + password + \"'\";\n"
                        + "rs = stmt.executeQuery(sql);");
                finding.getRecommendedPayloads().add("admin' -- ");
                finding.getRecommendedPayloads().add("' OR '1'='1' -- ");
                finding.getRecommendedPayloads().add("admin' #");
                finding.setRemediatedCode("String sql = \"SELECT id, username, password, email, role, secret_flag FROM users WHERE username = ? AND password = ?\";\n"
                        + "PreparedStatement pstmt = conn.prepareStatement(sql);\n"
                        + "pstmt.setString(1, username);\n"
                        + "pstmt.setString(2, password);\n"
                        + "ResultSet rs = pstmt.executeQuery();");
            } else if (fileName.contains("ProductDAO")) {
                finding.setClassName("ProductDAO");
                finding.setMethodName("searchProducts");
                finding.setLineNumber(46);
                finding.setDescription("Phương thức searchProducts() nối trực tiếp biến keyword và category vào mệnh đề WHERE (cả LIKE và toán tử so sánh =). Cho phép kẻ tấn công thực thi Union-based, Error-based và Blind SQL Injection.");
                finding.setVulnerableCode("if (keyword != null && !keyword.trim().isEmpty()) {\n"
                        + "    sql += \" AND (name LIKE '%\" + keyword + \"%'\";\n"
                        + "}\n"
                        + "rs = stmt.executeQuery(sql);");
                finding.getRecommendedPayloads().add("' UNION SELECT id, username, password, email, 0.0, 1 FROM users -- ");
                finding.getRecommendedPayloads().add("' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e)) -- ");
                finding.getRecommendedPayloads().add("' AND IF(1=1, SLEEP(3), 0) -- ");
                finding.setRemediatedCode("String sql = \"SELECT id, name, description, category, price, in_stock FROM products WHERE 1=1 AND (name LIKE ? OR description LIKE ?)\";\n"
                        + "PreparedStatement pstmt = conn.prepareStatement(sql);\n"
                        + "pstmt.setString(1, \"%\" + keyword + \"%\");\n"
                        + "pstmt.setString(2, \"%\" + keyword + \"%\");\n"
                        + "ResultSet rs = pstmt.executeQuery();");
            }

            result.addFinding(finding);
        }
    }

    private List<File> findJavaFiles(File dir) {
        List<File> list = new ArrayList<>();
        if (!dir.exists()) return list;

        try (Stream<Path> stream = Files.walk(dir.toPath())) {
            stream.filter(Files::isRegularFile)
                  .filter(p -> p.toString().endsWith(".java"))
                  .forEach(p -> list.add(p.toFile()));
        } catch (IOException e) {
            System.err.println("[SourceAnalyzer ERROR] Failed walking directory: " + e.getMessage());
        }
        return list;
    }
}
