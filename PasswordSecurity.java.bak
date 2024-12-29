
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class PasswordSecurity {

    // لیست رمزهای عبور رایج
    private static final List<String> COMMON_PASSWORDS = Arrays.asList(
            "123456", "password", "123456789", "qwerty", "abc123", "password1"
    );

    // بررسی امنیت رمز عبور
    public static String checkPasswordStrength(String password) {
        int score = 0;

        // بررسی طول
        if (password.length() >= 8) score++;
        else return "رمز عبور بسیار ضعیف است (کمتر از 8 کاراکتر)";

        // بررسی حروف بزرگ
        if (password.matches(".*[A-Z].*")) score++;

        // بررسی حروف کوچک
        if (password.matches(".*[a-z].*")) score++;

        // بررسی اعداد
        if (password.matches(".*\d.*")) score++;

        // بررسی کاراکترهای خاص
        if (password.matches(".*[!@#$%^&*()_+\-={}|\[\]:;"'<>,.?].*")) score++;

        // بررسی رمزهای رایج
        if (COMMON_PASSWORDS.contains(password)) return "رمز عبور بسیار ضعیف است (رمز رایج)";

        // امتیازدهی
        switch (score) {
            case 5: return "رمز عبور بسیار قوی است";
            case 4: return "رمز عبور قوی است";
            case 3: return "رمز عبور متوسط است";
            default: return "رمز عبور ضعیف است";
        }
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
        for (int i = 4; i < 12; i++) {
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }

        return password.toString();
    }

    // متد اصلی
    public static void main(String[] args) {
        String password = "P@ssword123";

        // بررسی رمز عبور
        System.out.println("امنیت رمز عبور: " + checkPasswordStrength(password));

        // تولید رمز عبور قوی
        System.out.println("رمز عبور پیشنهادی: " + generateStrongPassword());
    }
}
