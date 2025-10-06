package com.example.otp;

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

    // ✅ Admin emails
    private static final List<String> ADMIN_EMAILS = Arrays.asList(
        "de0049@srmist.edu.in",
        "aa0021@srmist.edu.in",
        "ls9964@srmist.edu.in",
        "hm1023@srmist.edu.in"
    );

    private final long TOKEN_EXPIRY = 10 * 60; // seconds

    public static void main(String[] args) {
        SpringApplication.run(OtpVerificationApp.class, args);
    }

    public OtpVerificationApp() {
        loadAllowedEmails();
        votes.putIfAbsent("POKEMON", 0);
        votes.putIfAbsent("DORAEMON", 0);
    }

    // ✅ Hardcoded allowed emails
    private void loadAllowedEmails() {
        List<String> emails = Arrays.asList(
            "nt4924@srmist.edu.in","ts5947@srmist.edu.in","bp3555@srmist.edu.in","bb4137@srmist.edu.in",
            "ak3655@srmist.edu.in","sv2309@srmist.edu.in","td4145@srmist.edu.in","hj7702@srmist.edu.in",
            "hs5385@srmist.edu.in","ls5324@srmist.edu.in","hn9608@srmist.edu.in","mr2228@srmist.edu.in",
            "ss0201@srmist.edu.in","jr9518@srmist.edu.in","sm0754@srmist.edu.in","jk5453@srmist.edu.in",
            "ar3156@srmist.edu.in","br6473@srmist.edu.in","vp7571@srmist.edu.in","ja0974@srmist.edu.in",
            "ss0742@srmist.edu.in","ah8334@srmist.edu.in","as5036@srmist.edu.in","sa1082@srmist.edu.in",
            "lk0168@srmist.edu.in","aa6792@srmist.edu.in","er0908@srmist.edu.in","ar3365@srmist.edu.in",
            "ds9601@srmist.edu.in","js3129@srmist.edu.in","ls9964@srmist.edu.in","sk0121@srmist.edu.in",
            "si0676@srmist.edu.in","pk6003@srmist.edu.in","ap8236@srmist.edu.in","pg7710@srmist.edu.in",
            "sr5861@srmist.edu.in","vj4895@srmist.edu.in","ba8689@srmist.edu.in","aa0021@srmist.edu.in",
            "ng7253@srmist.edu.in","mg9780@srmist.edu.in","tg8109@srmist.edu.in","ga0783@srmist.edu.in",
            "jp6684@srmist.edu.in","hg8771@srmist.edu.in","vk9901@srmist.edu.in","jc9099@srmist.edu.in",
            "na7036@srmist.edu.in","ss5513@srmist.edu.in","yk5611@srmist.edu.in","bj0162@srmist.edu.in",
            "kk5743@srmist.edu.in","hm1023@srmist.edu.in","ps6374@srmist.edu.in","aa1781@srmist.edu.in",
            "ps6195@srmist.edu.in","rm3661@srmist.edu.in","Kk6453@srmist.edu.in","de0049@srmist.edu.in",
            "naveenp1@srmist.edu.in","sakthits@srmist.edu.in"
        );
        allowedEmails.addAll(emails);
        System.out.println("✅ Loaded allowed emails: " + allowedEmails.size());
    }

    private String generateOtp() {
        int n = new Random().nextInt(900000) + 100000;
        return String.valueOf(n);
    }

    // ✅ Send OTP for login
    @PostMapping("/send-otp")
    public Map<String, Object> sendOtp(@RequestParam String email) {
        Map<String, Object> res = new HashMap<>();

        // Automatically append @srmist.edu.in if not present
        if (!email.contains("@")) {
            email = email + "@srmist.edu.in";
        }

        try {
            if (votedEmails.contains(email) && !ADMIN_EMAILS.contains(email)) {
                res.put("status", "error");
                res.put("message", "You have already voted. You cannot log in again.");
                return res;
            }
            if (!allowedEmails.contains(email) && !ADMIN_EMAILS.contains(email)) {
                res.put("status", "error");
                res.put("message", "Email not allowed");
                return res;
            }

            String otp = generateOtp();
            otpStorage.put(email, otp);

            sendEmail(email, "OTP for Voting", "<p>Your OTP for CR Voting is <b>" + otp + "</b> (valid 10 minutes)</p>");
            res.put("status", "ok");
            res.put("message", "OTP sent to " + email);
        } catch (Exception ex) {
            res.put("status", "error");
            res.put("message", "Failed to send OTP: " + ex.getMessage());
        }
        return res;
    }

    // ✅ Verify OTP
    @PostMapping("/verify-otp")
    public Map<String, Object> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        Map<String, Object> res = new HashMap<>();

        if (!email.contains("@")) {
            email = email + "@srmist.edu.in";
        }

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

    // ✅ Vote
    @PostMapping("/vote")
    public Map<String, Object> vote(@RequestParam String token, @RequestParam String candidate) {
        Map<String, Object> res = new HashMap<>();
        VerifiedInfo info = tokenStorage.get(token);

        if (info == null || isTokenExpired(info)) {
            res.put("status", "error");
            res.put("message", "Invalid or expired token");
            return res;
        }

        if (votedEmails.contains(info.email)) {
            res.put("status", "error");
            res.put("message", info.isAdmin ? "Admin has already voted." : "You have already voted.");
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

    // ✅ Admin OTP for results
    @PostMapping("/send-admin-otp")
    public Map<String, Object> sendAdminOtp() {
        Map<String, Object> res = new HashMap<>();
        String otp = generateOtp();
        try {
            for (String adminEmail : ADMIN_EMAILS) {
                otpStorage.put(adminEmail, otp);
                sendEmail(adminEmail, "Admin OTP for Results",
                        "<p>Your Admin OTP for viewing results is <b>" + otp + "</b> (valid 10 minutes)</p>");
            }
            res.put("status", "ok");
            res.put("message", "Admin OTP sent to all admins");
        } catch (Exception ex) {
            res.put("status", "error");
            res.put("message", "Failed to send admin OTP: " + ex.getMessage());
        }
        return res;
    }

    // ✅ Results
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
        double pp = total == 0 ? 0 : (p * 100.0 / total);
        double dp = total == 0 ? 0 : (d * 100.0 / total);
        String winner = p > d ? "POKEMON" : (d > p ? "DORAEMON" : "Tie");

        res.put("status", "ok");
        res.put("POKEMON", p);
        res.put("DORAEMON", d);
        res.put("total", total);
        res.put("percentages", Map.of("POKEMON", round(pp, 1), "DORAEMON", round(dp, 1)));
        res.put("winner", winner);
        return res;
    }

    @GetMapping("/whoami")
    public Map<String, Object> whoami(@RequestParam String token) {
        Map<String, Object> res = new HashMap<>();
        VerifiedInfo info = tokenStorage.get(token);
        if (info == null || isTokenExpired(info)) {
            res.put("status", "error");
            res.put("message", "Invalid or expired token");
            return res;
        }
        res.put("status", "ok");
        res.put("email", info.email);
        res.put("isAdmin", info.isAdmin);
        res.put("hasVoted", votedEmails.contains(info.email));
        return res;
    }

    private boolean isTokenExpired(VerifiedInfo info) {
        long now = Instant.now().getEpochSecond();
        return (now - info.issuedAt) > TOKEN_EXPIRY;
    }

    private static double round(double v, int places) {
        double factor = Math.pow(10, places);
        return Math.round(v * factor) / factor;
    }

    // ✅ Send email using Brevo
    private void sendEmail(String to, String subject, String htmlContent) throws Exception {
        String apiKey = System.getenv("BREVO_API_KEY");
        if (apiKey == null || apiKey.isEmpty()) {
            throw new RuntimeException("BREVO_API_KEY not set in environment variables");
        }

        String jsonBody = String.format("""
        {
          "sender": {"name": "Cartoon Voting", "email": "onetimeautheticator@gmail.com"},
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

        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 201 && response.statusCode() != 200) {
            throw new RuntimeException("Failed to send email: " + response.body());
        }
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
