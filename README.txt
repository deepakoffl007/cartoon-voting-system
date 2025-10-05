
CR Voting System - Full project
--------------------------------
Files:
- pom.xml
- src/main/java/com/example/otp/OtpVerificationApp.java
- src/main/resources/application.properties
- src/main/resources/static/index.html
- src/main/resources/static/vote.html
- src/main/resources/static/result.html

Instructions:
1. Place your allowed_emails.xlsx in the project root (same folder as pom.xml).
   Column A should contain header "Allowed Emails" and email addresses below it.
   Make sure admin email de0049@srmist.edu.in is allowed if you want to allow admin verification.

2. Edit src/main/resources/application.properties to enter your SMTP sender credentials:
   spring.mail.username=your_email@gmail.com
   spring.mail.password=your_app_password_or_app_specific_password

3. Build & run with Maven:
   mvn clean package
   mvn spring-boot:run
   or
   java -jar target/otp-verification-1.0.0.jar

4. Open browser:
   http://localhost:8080/index.html

Notes:
- Votes are stored in-memory (server restart clears them).
- Tokens expire after 10 minutes.
- This is a demo setup for classroom use only.
