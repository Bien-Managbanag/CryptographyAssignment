import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Assignment1 {
    public static void main(String[] args) throws Exception {
        //Prime modulus p and generator g
        BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);

        //Public Value A
        BigInteger A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);

        //Generate a random 1023 bit integer as secret value b
        SecureRandom secureRandom = new SecureRandom();
        BigInteger b = new BigInteger(1023, secureRandom);

        //Calculate public shared value B
        BigInteger B = modExp(g, b, p);

        //Calculate shared secret s
        BigInteger s = modExp(A, b, p);

        //Convert shared secret to byte array & remove any leading zeros
        byte[] sBytes = s.toByteArray();
        if (sBytes[0] == 0) {
            sBytes = Arrays.copyOfRange(sBytes, 1, sBytes.length);
        }

        //Generate AES key by hasing the shared secret with SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] key = sha256.digest(sBytes);

        //Generate a 128 bit IV
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        //AES encryption with CBC mode
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        
        //Read files & encrypt
        Path filePath = Paths.get(args[0]);
        byte[] fileBytes = Files.readAllBytes(filePath);
        byte[] paddedFileBytes = applyPadding(fileBytes);

        byte[] encryptedBytes = cipher.doFinal(paddedFileBytes);

        //Output required files and values
        writeToFile("DH.txt", bytesToHex(B.toByteArray()));             //Write B to DH.txt
        writeToFile("IV.txt", bytesToHex(ivBytes));                     //Write IV to IV.txt
        writeToFile("Encryption.txt", bytesToHex(encryptedBytes));      //Write encrypted output to Encryption.txt
    }

    //Modular exponentiation using the right-to-left binary method
    public static BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        BigInteger currentPower = base.mod(modulus);

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.and(BigInteger.ONE).equals(BigInteger.ONE)) {
                result = result.multiply(currentPower).mod(modulus);
            }
            currentPower = currentPower.multiply(currentPower).mod(modulus);
            exponent = exponent.shiftRight(1);
        }
        return result;
    }

    
    public static byte[] applyPadding(byte[] data) {
        int blockSize = 16;
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        // Start padding with 1 bit (0x80 in hex)
        paddedData[data.length] = (byte) 0x80;
        // Remaining padding bytes are left as 0x00
        return paddedData;
    }

    //Convert byte array to hexadecimal string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    //Write string to a file
    public static void writeToFile(String fileName, String data) throws IOException {
        Path path = Paths.get(fileName);
        Files.write(path, data.getBytes());
    }
}
