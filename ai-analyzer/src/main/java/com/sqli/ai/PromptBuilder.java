package com.sqli.ai;

/**
 * Builds optimized prompts for Generative AI to perform Static Application Security Testing (SAST).
 */
public class PromptBuilder {

    /**
     * System prompt establishing the persona and analytical framework.
     */
    public static String buildSystemPrompt() {
        return "You are an elite Application Security Researcher and Principal AppSec Code Auditor specializing in "
             + "Java Enterprise Applications, OWASP Top 10 vulnerabilities, and SQL Injection (CWE-89).\n"
             + "Your task is to review Java source code, perform Taint Analysis (tracing sources to sinks), identify "
             + "dangerous SQL statement concatenations, formulate realistic exploit payloads, and provide secure remediation "
             + "using parameterized queries (PreparedStatement).\n\n"
             + "Always structure your findings clearly:\n"
             + "1. Vulnerability Type & CWE\n"
             + "2. Exact Code Location (File, Method, Line number)\n"
             + "3. Root Cause Analysis (Taint Source -> Sink flow)\n"
             + "4. Exploitability Assessment & Specific Exploitation Payloads (Auth Bypass, Union, Error-based, Blind)\n"
             + "5. Secure Remediation with before/after code blocks.\n";
    }

    /**
     * User prompt providing the source code context and instructions.
     */
    public static String buildUserPrompt(String fileName, String sourceCode) {
        return "Please perform an in-depth security analysis on the following Java source file for SQL Injection vulnerabilities:\n\n"
             + "File: " + fileName + "\n"
             + "```java\n"
             + sourceCode + "\n"
             + "```\n\n"
             + "Please provide:\n"
             + "- Is there any SQL Injection vulnerability? (YES/NO)\n"
             + "- What is the Taint Source and what is the Taint Sink?\n"
             + "- Concrete exploit payloads that can be used against this endpoint:\n"
             + "    * For authentication endpoints: Payloads to bypass login.\n"
             + "    * For search/query endpoints: Payloads for Union-based data extraction, Error-based extraction, and Time-based Blind SQLi.\n"
             + "- The refactored secure version of the code using Java PreparedStatement.\n";
    }
}
