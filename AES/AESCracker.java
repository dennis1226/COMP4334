import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESCracker {
    public static void main(String[] args) throws Exception {
		
		
		
		//setting a plaintext
        String plaintext = "hello this is just plaintext abcd i love polyu";
		
        // assume that we need to know one plain text, it would easy to recover the plaintext
        String plaintextKnown = "hello";
        byte[] plaintextKnownByte = plaintextKnown.getBytes(StandardCharsets.UTF_8);
		
        // number of known bytes of the key
        int numberKeyBytes = 14; // 14 bytes
		
        // create a random key & iv
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16]; // 16 byte
        random.nextBytes(key);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        System.out.println("key length:" + key.length + ", key: " + bytesToHex(key));
		System.out.println("IV length: " + iv.length + ", IV: " + bytesToHex(iv));
        // setup AES-CBC working statge
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		//use AES CBC , then Data is grouped according to a certain size
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
		
        // get plaintext
        byte[] plaintextByte = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertextByte = cipher.doFinal(plaintextByte);


		System.out.println("ciphertext length: " + ciphertextByte.length + " ciphertext: " + bytesToHex(ciphertextByte));
		
		
		// print the assumpt known
        byte[] keyGuessed = new byte[16];
        System.arraycopy(key, 0, keyGuessed, 0, numberKeyBytes ); // copy first 14 bytes
        System.out.println("keyGuess length: " + keyGuessed.length + " data: " + bytesToHex(keyGuessed));
		byte[] ivGuessed = new byte[16];
		System.arraycopy(iv, 0, ivGuessed, 0, numberKeyBytes ); // copy first 14 bytes
        System.out.println("ivGuess length: " + ivGuessed.length + " data: " + bytesToHex(ivGuessed));
		
        for (int a = 0; a < 256; a++) {
            for (int b = 0; b < 256; b++) {
                for (int c = 0; c < 256; c++) {
                    for (int d = 0; d < 256; d++) {
                        keyGuessed[15] = (byte) d;
                        decryptAesCbc128(keyGuessed, iv, ciphertextByte, plaintextKnownByte);
                    }
                    keyGuessed[14] = (byte) c;
                }
                keyGuessed[13] = (byte) b;
            }
            keyGuessed[12] = (byte) a;
        }
		
	
    }

    private static boolean decryptAesCbc128(byte[] key, byte[] iv, byte[] ciphertext, byte[] plaintextbyteKnown) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        //cal time
		long startTime = System.nanoTime();
		//use AES Method
		SecretKeySpec keySpecificDecode = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameter = new IvParameterSpec(iv);
		//use AES CBC , then Data is grouped according to a certain size
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, keySpecificDecode, ivParameter);
        byte[] decryptedtext = new byte[0];
        try {
			//try to decrypt it
            decryptedtext = cipherDecrypt.doFinal(ciphertext);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            //e.printStackTrace();
            return false;
        }
        // partial array comparison
        boolean found = ByteBuffer.wrap(decryptedtext, 0, 5).equals(ByteBuffer.wrap(plaintextbyteKnown, 0, 5));
        if (found == false) {return false;}
        System.out.println("*** key found ***");
        System.out.println("key length: " + key.length + " key: " + bytesToHex(key));
		System.out.println("iv length: " + iv.length + " iv: " + bytesToHex(iv));
		
        System.out.println("plaintext: " + new String(decryptedtext));
		
		//cal time
		long endTime   = System.nanoTime();
		long totalTime = endTime - startTime;
		System.out.println("Time:"+ totalTime + "nanosecond");
		
        System.exit(0);
        return true;
    }

	//change back to hex, so that we can see the final result
    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}