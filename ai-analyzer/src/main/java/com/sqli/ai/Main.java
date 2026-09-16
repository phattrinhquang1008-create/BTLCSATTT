package com.sqli.ai;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * CLI Entry point for AI-powered SQL Injection SAST Analyzer.
 */
public class Main {

    public static void main(String[] args) {
        printBanner();

        // 1. Resolve Target Directory
        String targetPath = args.length > 0 ? args[0] : "../vulnerable-web/src/main/java";
        File targetDir = new File(targetPath);

        // Fallback relative to current directory if running from project root
        if (!targetDir.exists()) {
            File alt = new File("vulnerable-web/src/main/java");
            if (alt.exists()) {
                targetDir = alt;
            }
        }

        System.out.println("[*] Target Source Directory: " + targetDir.getAbsolutePath());
        if (!targetDir.exists()) {
            System.err.println("[!] ERROR: Target directory does not exist. Please specify a valid Java source folder.");
            System.exit(1);
        }

        // 2. Resolve Output Report Path
        String outputPath = args.length > 1 ? args[1] : "../reports/ai-analysis/ai_findings_report.md";
        File outputFile = new File(outputPath);
        if (!outputFile.getParentFile().exists()) {
            outputFile = new File("reports/ai-analysis/ai_findings_report.md");
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
        }

        // 3. Initialize AI Client and Scanner
        AIClient aiClient = new AIClient();
        SourceAnalyzer analyzer = new SourceAnalyzer(aiClient);

        System.out.println("[*] Starting SAST Scan with Generative AI Engine...");
        long start = System.currentTimeMillis();
        AnalysisResult result = analyzer.analyzeDirectory(targetDir);
        long duration = System.currentTimeMillis() - start;

        // 4. Print Summary to Console
        System.out.println("\n" + "=".repeat(60));
        System.out.println("  SCAN COMPLETE in " + duration + " ms");
        System.out.println("=".repeat(60));
        System.out.println("  - Total Java Files Scanned : " + result.getFilesScanned());
        System.out.println("  - Vulnerable Files Detected: " + result.getVulnerableFilesCount());
        System.out.println("  - Sinks Identified         : " + result.getFindings().size());
        System.out.println("=".repeat(60));

        // 5. Generate and Save Markdown Report
        String markdown = result.toMarkdownReport();
        try {
            Files.writeString(outputFile.toPath(), markdown);
            System.out.println("[+] Executive Security Report generated successfully at:\n    " + outputFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("[!] Failed to write markdown report: " + e.getMessage());
        }

        System.out.println("\n[*] Next Step: Review attacks/ directory to execute recommended payloads against vulnerable-web!");
    }

    private static void printBanner() {
        System.out.println("""
            =============================================================
             __  __  ___  _     ___        _    ___ 
            / _|| _ \\| | | |   /   \\      / \\  |_ _|
            \\_ \\|  _/| | | |__ | - | === / _ \\  | | 
            |__/|_|  |_| |____||_|_|    /_/ \\_\\|___|
            
             AI-Powered Java SQL Injection SAST Scanner
             Course: An Toan Thong Tin (Information Security)
            =============================================================
            """);
    }
}
