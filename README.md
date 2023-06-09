# tugas-algoritma-enkripsi

public class CaesarEncryption {
    public static String encrypt(String plaintext, int shift) {
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < plaintext.length(); i++) {
            char currentChar = plaintext.charAt(i);
            if (Character.isLetter(currentChar)) {
                char encryptedChar = (char) ((currentChar - 'A' + shift) % 26 + 'A');
                ciphertext.append(encryptedChar);
            } else {
                ciphertext.append(currentChar);
            }
        }
        return ciphertext.toString();
    }

    public static void main(String[] args) {
        String plaintext = "HELLO";
        int shift = 3;
        String ciphertext = encrypt(plaintext, shift);
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext: " + ciphertext);
    }
}


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;

public class RSAEncryption {
    public static String encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Masukan plaintext: ");
        String plaintext = scanner.nextLine();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String encryptedText = encrypt(plaintext, publicKey);
        String decryptedText = decrypt(encryptedText, privateKey);

        System.out.println("Plaintext: " + plaintext);
        System.out.println("Encrypted Text: " + encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);

        scanner.close();
    }
}


public class SimpleSubstitutionEncryption {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String SUBSTITUTION = "DEFGHIJKLMNOPQRSTUVWXYZABC";

    public static String encrypt(String plaintext) {
        StringBuilder ciphertext = new StringBuilder();
        plaintext = plaintext.toUpperCase();
        for (int i = 0; i < plaintext.length(); i++) {
            char currentChar = plaintext.charAt(i);
            if (Character.isLetter(currentChar)) {
                int index = ALPHABET.indexOf(currentChar);
                char encryptedChar = SUBSTITUTION.charAt(index);
                ciphertext.append(encryptedChar);
            } else {
                ciphertext.append(currentChar);
            }
        }
        return ciphertext.toString();
    }

    public static void main(String[] args) {
        String plaintext = "HELLO";
        String ciphertext = encrypt(plaintext);
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext: " + ciphertext);
    }
}


public class VigenereEncryption {
    public static String encrypt(String plaintext, String key) {
        StringBuilder ciphertext = new StringBuilder();
        int keyLength = key.length();
        for (int i = 0; i < plaintext.length(); i++) {
            char currentChar = plaintext.charAt(i);
            char keyChar = key.charAt(i % keyLength);
            if (Character.isLetter(currentChar)) {
                char encryptedChar = (char) ((currentChar - 'A' + keyChar - 'A') % 26 + 'A');
                ciphertext.append(encryptedChar);
            } else {
                ciphertext.append(currentChar);
            }
        }
        return ciphertext.toString();
    }

    public static void main(String[] args) {
        String plaintext = "HELLO";
        String key = "KEY";
        String ciphertext = encrypt(plaintext, key);
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext: " + ciphertext);
    }
}
