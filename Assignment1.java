import java.io.*;
import java.math.BigInteger;
import java.security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;
import javax.crypto.*;
import javax.crpto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Assignment1  {
    //Constants
    private static final String PRIME_MODULUS_HEX = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
    private static final String GENERATOR_HEX = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
    private static final String PUBLIC_SHARED_VALUE_A_HEX = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";

    public static void main(String[] args) throws Exception {
        //Parse the hexadecimals constants to BigInteger
        BigInteger p = new BigInteger(PRIME_MODULUS_HEX, 16);
        BigInteger g = new BigInteger(GENERATOR_HEX, 16);
        BigInteger A = new BigInteger(PUBLIC_SHARED_VALUE_A_HEX, 16);

        //Generate a 1023-bit random integer as secret value
        SecureRandom random = new SecureRandom;
        BigInteger b = new BigInteger(1023, random);
        
        //Calculate publi shared value B
        BigInteger B = squareAndMultiply(g, b, p);

        //Calulate shared secret s
        BigInteger s = squareAndMultiply(A, b, p);

        //Hash shared secret s with SHA-256 to get the AES
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] k = sha256.digest(s.toByteArray());

        //Read input binary file and encrypt using AES in CBC
        if (args.length < 1) {
            System.err.println("Please provide the input filename as the first argument.");
            return;
        }

        String inputFilename = args[0];
        byte[] inputFileBytes = readFile(inputFilename);

        //Generate random 128-bit IV
        byte[] iv = new byte[16]; // 128 bits / 8 = 16 bytes
        random.nextBytes(iv);
        
        //Encrypt file with AES
        byte[] encryptedFileBytes = encryptAES_CBC(k, iv, inputFileBytes);

        //Write outputs
        writeToFile("DH.txt", B.toString(16));
        writeToFile("IV.txt", bytesToHex(iv));
        writeToFile("Encryption.txt", bytesToHex(encryptedFileBytes));
    }

    // Implement the square-and-multiply algorithm (left-to-right method)
    private static BigInteger squareAndMultiply (BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        String binaryExponent = exponent/toString(2);
        for (int i=0; i < binaryExponent.length(); i++) {
            result = result.multiply(result).mod(modulus);
            if (binaryExponent.charAt(i) == '1') {
                result = result.multiply(base).mod(modulus);
            }
        }
        return result;
    }

    // Read file into byte array
    private static byte[] readFile(String filename) throws IOException {
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] bytes = new byte[(int) file.length()];
        fis.read(bytes);
        fis.close();
        return bytes;
    }

    // AES encryption in CBC mode with custom padding
    private static byte[] encryptAES_CBC(byte[] key, byte[] iv, byte data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        AlgorithmParameterSpec ivSpec = new IVParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // Apply custom padding
        int blockSize = cipher.getBlockSize();
        byte[] paddedData = pad(data, blockSize);

        return cipher.doFinal(paddedData);
    }

    // Custom padding
    private static byte[] pad(byte[] data, int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        paddedData[data.length] = (byte) 0x80; // append 1 bit followed by 0 bits
        return paddedData;
    }

    // Write byte array to file
    private static void writeToFile(String filename, String data) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            writer.write(data);
        }
    }

    // Convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }


}