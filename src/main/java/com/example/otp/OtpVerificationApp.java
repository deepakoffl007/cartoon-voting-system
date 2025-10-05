package com.example.otp;

import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
@RequestMapping("/auth")
public class OtpVerificationApp {

    private final ConcurrentHashMap<String, String> otpStorage = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, VerifiedInfo> tokenStorage = new ConcurrentHashMap<>();
    private final Set<String> allowedEmails = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Integer> votes = new ConcurrentHashMap<>();
    private final Set<String> votedEmails = ConcurrentHashMap.newKeySet();

    private volatile boolean votingOpen = false; // ✅ controlled by admin

    private static final List<String> ADMIN_EMAILS = Arrays.asList(
            "de0049@srmist.edu.in",
            "aa0021@srmist.edu.in",
            "ls9964@srmist.edu.in",
            "hm1023@srmist.edu.in"
    );

    private final long TOKEN_EXPIRY = 10 * 60; // 10 min

    public static void main(String[] args) {
        SpringApplication.run(OtpVerificationApp.class, args);
    }

    public OtpVerificationApp() {
        loadAllowedEmails();
        votes.putIfAbsent("POKEMON", 0);
        votes.putIfAbsent("DORAEMON", 0);
    }

    private void loadAllowedEmails() {
        try (FileInputStream fis = new FileInputStream("allowed_emails.xlsx");
             Workbook workbook = new XSSFWorkbook(fis)) {
            Sheet sheet = workbook.getSheetAt(0);
            for (Row row : sheet) {
                Cell cell = row.getCell(0);
                if (cell != null) {
                    String email = cell.getStringCellValue().trim();
                    if (!email.isEmpty()) allowedEmails.add(email);
                }
            }
            System.out.println("✅ Loaded allowed emails: " + allowedEmails.size());
        } catch (Exception e) {
            System.out.println("⚠️ Could not load allowed_emails.xlsx: " + e.getMessage());
        }
    }

    private String generateOtp() {
        return String.valueOf(new Random().nextInt(900000) + 100000);
    }

    @PostMapping("/send-otp")
    public Map<String, Object> sendOtp(@RequestParam String email) {
        Map<String, Object> res = new HashMap<>();
        try {
            if (votedEmails.contains(email) && !ADMIN_EMAILS.contains(email)) {
                res.put("status", "error");
                res.put("message", "You have already voted.");
                return res;
            }
            if (!allowedEmails.contains(email) && !ADMIN_EMAILS.contains(email)) {
                res.put("status", "error");
                res.put("message", "Email not allowed");
                return res;
            }
            String otp = generateOtp();
            otpStorage.put(email, otp);
            sendEmail(email, "OTP for Voting",
                    "<p>Your OTP for CR Voting is <b>" + otp + "</b> (valid 10 minutes)</p>");
            res.put("status", "ok");
            res.put("message", "OTP sent to " + email);
        } catch (Exception ex) {
            res.put("status", "error");
            res.put("message", "Failed to send OTP: " + ex.getMessage());
        }
        return res;
    }

    @PostMapping("/verify-otp")
    public Map<String, Object> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        Map<String, Object> res = new HashMap<>();
        String stored = otpStorage.get(email);
        if (stored != null && stored.equals(otp)) {
            otpStorage.remove(email);
            String token = UUID.randomUUID().toString();
            boolean isAdmin = ADMIN_EMAILS.contains(email);
            tokenStorage.put(token, new VerifiedInfo(email, isAdmin, Instant.now().getEpochSecond()));
            res.put("status", "ok");
            res.put("token", token);
            res.put("isAdmin", isAdmin);
        } else {
            res.put("status", "error");
            res.put("message", "Invalid OTP");
        }
        return res;
    }

    @PostMapping("/vote")
    public Map<String, Object> vote(@RequestParam String token, @RequestParam String candidate) {
        Map<String, Object> res = new HashMap<>();
        if (!votingOpen) {
            res.put("status", "error");
            res.put("message", "Voting is temporarily closed.");
            return res;
        }
        VerifiedInfo info = tokenStorage.get(token);
        if (info == null || isTokenExpired(info)) {
            res.put("status", "error");
            res.put("message", "Invalid or expired token");
            return res;
        }
        if (votedEmails.contains(info.email)) {
            res.put("status", "error");
            res.put("message", "You have already voted.");
            return res;
        }
        if (!"POKEMON".equals(candidate) && !"DORAEMON".equals(candidate)) {
            res.put("status", "error");
            res.put("message", "Invalid candidate");
            return res;
        }
        votes.merge(candidate, 1, Integer::sum);
        votedEmails.add(info.email);
        res.put("status", "ok");
        res.put("message", "Vote counted for " + candidate);
        return res;
    }

    @PostMapping("/send-admin-otp")
    public Map<String, Object> sendAdminOtp() {
        Map<String, Object> res = new HashMap<>();
        String otp = generateOtp();
        try {
            for (String adminEmail : ADMIN_EMAILS) {
                otpStorage.put(adminEmail, otp);
                sendEmail(adminEmail, "Admin OTP for Results",
                        "<p>Your Admin OTP for viewing results is <b>" + otp + "</b></p>");
            }
            res.put("status", "ok");
            res.put("message", "Admin OTP sent");
        } catch (Exception ex) {
            res.put("status", "error");
            res.put("message", "Failed to send admin OTP: " + ex.getMessage());
        }
        return res;
    }

    @GetMapping("/results")
    public Map<String, Object> results(@RequestParam String token) {
        Map<String, Object> res = new HashMap<>();
        VerifiedInfo info = tokenStorage.get(token);
        if (info == null || isTokenExpired(info) || !info.isAdmin) {
            res.put("status", "error");
            res.put("message", "Only admin can view results");
            return res;
        }
        int p = votes.getOrDefault("POKEMON", 0);
        int d = votes.getOrDefault("DORAEMON", 0);
        int total = p + d;
        String winner = p > d ? "POKEMON" : (d > p ? "DORAEMON" : "Tie");
        res.put("status", "ok");
        res.put("POKEMON", p);
        res.put("DORAEMON", d);
        res.put("total", total);
        res.put("winner", winner);
        res.put("votingOpen", votingOpen);
        return res;
    }

    @PostMapping("/start-voting")
    public Map<String, Object> startVoting(@RequestParam String token) {
        Map<String, Object> res = new HashMap<>();
        VerifiedInfo info = tokenStorage.get(token);
        if (info == null || !info.isAdmin) {
            res.put("status", "error");
            res.put("message", "Only admin can start voting.");
            return res;
        }
        votingOpen = true;
        res.put("status", "ok");
        res.put("message", "Voting started.");
        return res;
    }

    @PostMapping("/stop-voting")
    public Map<String, Object> stopVoting(@RequestParam String token) {
        Map<String, Object> res = new HashMap<>();
        VerifiedInfo info = tokenStorage.get(token);
        if (info == null || !info.isAdmin) {
            res.put("status", "error");
            res.put("message", "Only admin can stop voting.");
            return res;
        }
        votingOpen = false;
        res.put("status", "ok");
        res.put("message", "Voting stopped.");
        return res;
    }

    private boolean isTokenExpired(VerifiedInfo info) {
        return (Instant.now().getEpochSecond() - info.issuedAt) > TOKEN_EXPIRY;
    }

    private void sendEmail(String to, String subject, String htmlContent) throws Exception {
        String apiKey = System.getenv("BREVO_API_KEY");
        if (apiKey == null || apiKey.isEmpty()) throw new RuntimeException("BREVO_API_KEY not set");

        String jsonBody = String.format("""
        {
          "sender": {"name": "Cartoon Voting", "email": "no-reply@cartoonvoting.com"},
          "to": [{"email": "%s"}],
          "subject": "%s",
          "htmlContent": "%s"
        }
        """, to, subject, htmlContent);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.brevo.com/v3/smtp/email"))
                .header("accept", "application/json")
                .header("api-key", apiKey)
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> response =
                HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 201 && response.statusCode() != 200)
            throw new RuntimeException("Failed to send email: " + response.body());
    }

    private static class VerifiedInfo {
        public final String email;
        public final boolean isAdmin;
        public final long issuedAt;
        public VerifiedInfo(String email, boolean isAdmin, long issuedAt) {
            this.email = email;
            this.isAdmin = isAdmin;
            this.issuedAt = issuedAt;
        }
    }
}
