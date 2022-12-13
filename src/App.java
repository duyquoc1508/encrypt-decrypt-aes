import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class App {
    public static void main(String[] args) throws Exception {
        String message = "Hello Merchant! Im PayGate";
        String key = "78B8B5E54FAC233E1AF050B77052F79948DACDD83E18E428C1757195A8020376";
        String resultEncrypt = encryptAES(message, key);
        System.out.println("resultEncrypt: " + resultEncrypt);

        // String encryptedStr = "CUuirQPe6LOZ6qyZRgzIBVGXrWh0uhp2GbyvG7qWTwM=";
        // String resultDecrypt = decryptAES(encryptedStr, key);
        // System.out.println("resultDecrypt: " + resultDecrypt);
    }

    public static String encryptAES(String data, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            byte[] iv = Arrays.copyOf(Hex.decodeHex(key), 16);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKey priKey = new SecretKeySpec(Hex.decodeHex(key), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, priKey, ivParameterSpec);
            byte[] plainText = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(plainText);
        } catch (Exception e) {
            e.printStackTrace();
        };
        return "";
       }

       public static String decryptAES(String data, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            byte[] iv = Arrays.copyOf(Hex.decodeHex(key), 16);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKey priKey = new SecretKeySpec(Hex.decodeHex(key), "AES");
            cipher.init(Cipher.DECRYPT_MODE, priKey, ivParameterSpec);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(data));
            return new String(plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
       }


    public static int getCheckDigit(String number) {
        int sum = 0;
        for (int i = 0; i < number.length(); i++) {
        // Get the digit at the current position.
            int digit = Integer.parseInt(number.substring(i, (i + 1)));
            if ((i % 2) == 0) {
                digit = digit * 2;
                if (digit > 9) {
                    digit = (digit / 10) + (digit % 10);
                }
            }
            sum += digit;
            System.out.println(sum);
        }
        // The check digit is the number required to make the sum a multiple of
        // 10.
        int mod = sum % 10;
        return ((mod == 0) ? 0 : 10 - mod);
        }

}
