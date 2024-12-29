import org.mindrot.jbcrypt.BCrypt;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;

public class AdvancedPasswordSecurity {

    // لیست رمزهای عبور رایج
    private static final List<String> COMMON_PASSWORDS = Arrays.asList(
            "123456", "password", "123456789", "qwerty", "abc123", "password1"
    );

    // بررسی امنیت رمز عبور با الگوریتم‌های پیچیده‌تر
    public static String checkPasswordStrength(String password) {
        int score = 0;

        // بررسی طول رمز عبور (حداقل 12 کاراکتر)
        if (password.length() >= 12) score++;
        else return "Password is too weak (less than 12 characters)";

        // بررسی حروف بزرگ
        if (password.matches(".*[A-Z].*")) score++;

        // بررسی حروف کوچک
        if (password.matches(".*[a-z].*")) score++;

        // بررسی اعداد
        if (password.matches(".*\\d.*")) score++;

        // بررسی کاراکترهای خاص
        if (password.matches(".*[!@#$%^&*()_+\\-={}\\[\\]:;\"'<>,.?/].*")) score++;

        // بررسی رمزهای رایج
        if (COMMON_PASSWORDS.contains(password)) return "Password is too weak (common password)";

        // جلوگیری از استفاده از کلمات دیکشنری ساده
        if (isDictionaryWord(password)) return "Password is too weak (dictionary word)";

        // جلوگیری از استفاده از اطلاعات شخصی (مثلاً تاریخ تولد)
        if (containsPersonalInfo(password)) return "Password is too weak (personal information)";

        // امتیازدهی
        switch (score) {
            case 5: return "Password is very strong";
            case 4: return "Password is strong";
            case 3: return "Password is medium";
            default: return "Password is weak";
        }
    }

    // بررسی اینکه آیا رمز عبور یک کلمه دیکشنری است یا خیر
    private static boolean isDictionaryWord(String password) {
       
        List<String> dictionaryWords = Arrays.asList("password", "qwerty", "admin", "welcome", "letmein");
        return dictionaryWords.contains(password.toLowerCase());
    }

    // بررسی وجود اطلاعات شخصی در رمز عبور (مانند تاریخ تولد، شماره تلفن)
    private static boolean containsPersonalInfo(String password) {
        // به عنوان مثال، اینجا فقط تاریخ تولد را بررسی می‌کنیم.
        String[] personalInfoPatterns = {
            "\\d{4}-\\d{2}-\\d{2}", // YYYY-MM-DD
            "\\d{8}" // تاریخ تولد به فرمت YYYYMMDD
        };
        
        for (String pattern : personalInfoPatterns) {
            if (password.matches(".*" + pattern + ".*")) {
                return true;
            }
        }
        return false;
    }

    // هش کردن رمز عبور با استفاده از الگوریتم PBKDF2
    public static String hashPasswordPBKDF2(String password) throws Exception {
        int iterations = 10000;
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return bytesToHex(salt) + ":" + bytesToHex(hash);
    }

    // تبدیل بایت‌ها به رشته هگزا دسیمال
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // مقایسه رمز عبور با هش PBKDF2
    public static boolean checkPasswordPBKDF2(String password, String storedHash) throws Exception {
        String[] parts = storedHash.split(":");
        byte[] salt = hexToBytes(parts[0]);
        byte[] storedHashBytes = hexToBytes(parts[1]);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();

        return Arrays.equals(storedHashBytes, hash);
    }

    // تبدیل رشته هگزا دسیمال به بایت
    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    // تولید رمز عبور قوی
    public static String generateStrongPassword() {
        String upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerCase = "abcdefghijklmnopqrstuvwxyz";
        String numbers = "0123456789";
        String specialChars = "!@#$%^&*()_+-=";
        String allChars = upperCase + lowerCase + numbers + specialChars;

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        // اضافه کردن حداقل یک کاراکتر از هر نوع
        password.append(upperCase.charAt(random.nextInt(upperCase.length())));
        password.append(lowerCase.charAt(random.nextInt(lowerCase.length())));
        password.append(numbers.charAt(random.nextInt(numbers.length())));
        password.append(specialChars.charAt(random.nextInt(specialChars.length())));

        // تکمیل رمز عبور با کاراکترهای تصادفی
        for (int i = 4; i < 20; i++) {  // طول رمز عبور را به 20 افزایش داده‌ایم
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }

        return password.toString();
    }

    // متد اصلی
    public static void main(String[] args) {
        String password = "P@ssw0rd123!";

        // بررسی رمز عبور
        System.out.println("Password Strength: " + checkPasswordStrength(password));

        try {
            // هش کردن رمز عبور با PBKDF2
            String hashedPasswordPBKDF2 = hashPasswordPBKDF2(password);
            System.out.println("Hashed Password (PBKDF2): " + hashedPasswordPBKDF2);

            // مقایسه رمز عبور با هش
            System.out.println("Password matches hash: " + checkPasswordPBKDF2(password, hashedPasswordPBKDF2));
        } catch (Exception e) {
            e.printStackTrace();
        }

        // تولید رمز عبور قوی
        System.out.println("Generated Strong Password: " + generateStrongPassword());
    }
}
