//@Credit to https://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/

package encryption;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class StrongPasswordGenerator {


    private final String password;

    public StrongPasswordGenerator(String password) {
        this.password = password;
    }

    public String generateStrongPasswordHash() throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        int iterations = 45000;
        char[] chars = password.toCharArray();
        byte[] salt = getSalt();
        return genPassword(salt,chars,iterations);
    }



    public String generateStrongPasswordHash(byte[] Salt) throws NoSuchAlgorithmException, InvalidKeySpecException{
        int iterations = 45000;
        char[] chars = password.toCharArray();
        byte[] salt = Salt;
        return genPassword(salt,chars,iterations);
    }


    public String genPassword(byte[] salt, char[] chars, int iterations) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 2);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return iterations + ":" + toHex(salt) + ":" + toHex(hash) ;

    }

    private byte[] getSalt() throws NoSuchAlgorithmException
    {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[16];
            sr.nextBytes(salt);
            return salt;
    }

    private String toHex(byte[] array) throws NoSuchAlgorithmException
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }
        else{
            return hex;
        }
    }

}
