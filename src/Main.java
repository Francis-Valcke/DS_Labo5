import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try {
            Person person1 = new Person("Valcking", "Waregem", "056326680");
            Person person2 = new Person("Jern_97", "Brugge", "050861669");
            Person person1fake = new Person("Valcking", "Waregem", "056326681");

            byte[] person1bytes = person1.getBytes();
            byte[] person2bytes = person2.getBytes();
            byte[] person1fakebytes = person1fake.getBytes();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash1 = digest.digest(person1bytes);
            byte[] hash2 = digest.digest(person2bytes);
            byte[] hash1fake = digest.digest(person1fakebytes);

            System.out.println("****HASHING");
            System.out.println(Base64.getEncoder().encodeToString(person1bytes));
            System.out.println(Base64.getEncoder().encodeToString(hash1));
            System.out.println();
            System.out.println(Base64.getEncoder().encodeToString(person2bytes));
            System.out.println(Base64.getEncoder().encodeToString(hash2));
            System.out.println();
            System.out.println(Base64.getEncoder().encodeToString(person1fakebytes));
            System.out.println(Base64.getEncoder().encodeToString(hash1fake));
            System.out.println();


            System.out.println("****** SYMMETRIC ENCRYPTION");
            long aesTime = System.currentTimeMillis();
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            for (int i = 0; i < 1; i++) {
                Key aesKey = keygen.generateKey();
                Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] encrypted = aesCipher.doFinal("Qwerty Overlord".getBytes());
                System.out.println(Base64.getEncoder().encodeToString(encrypted));
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
                byte[] decrypted = aesCipher.doFinal(encrypted);
                System.out.println(new String(decrypted));
            }
            System.out.println("time:" + (System.currentTimeMillis() - aesTime));


            System.out.println("****** ASYMMETRIC ENCRYPTION");
            long rsaTime = System.currentTimeMillis();
            for (int i = 0; i < 1; i++) {
                KeyPairGenerator keypairgen = KeyPairGenerator.getInstance("RSA");
                KeyPair rsaKeypair = keypairgen.generateKeyPair();
                keypairgen.initialize(4096);
                PrivateKey rsaPrivate = rsaKeypair.getPrivate();
                PublicKey rsaPublic = rsaKeypair.getPublic();
                //System.out.println("PUBLIC KEY:" + Base64.getEncoder().encodeToString(rsaPublic.getEncoded()));
                Cipher rsaCipher = Cipher.getInstance("RSA");
                rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPublic);
                byte[] encrypted = rsaCipher.doFinal("Qwerty Overlord".getBytes());
                //System.out.println(Base64.getEncoder().encodeToString(encrypted));
                rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivate);
                byte[] decrypted = rsaCipher.doFinal(encrypted);
                //System.out.println(new String(decrypted));
            }
            System.out.println("time:" + (System.currentTimeMillis() - rsaTime));
            System.out.println();

            System.out.println("****** SIGNATURE");
            Signature rsa = Signature.getInstance("SHA256withRSA");
            KeyPairGenerator keypairgen = KeyPairGenerator.getInstance("RSA");
            KeyPair rsaKeypair = keypairgen.generateKeyPair();
            keypairgen.initialize(4096);
            PrivateKey rsaPrivate = rsaKeypair.getPrivate();
            PublicKey rsaPublic = rsaKeypair.getPublic();
            rsa.initSign(rsaPrivate);
            rsa.update(person2bytes);
            byte[] sig = rsa.sign();
            System.out.println("Person2 :" + Base64.getEncoder().encodeToString(person2bytes));
            System.out.println("SIGN: " + Base64.getEncoder().encodeToString(sig));

            rsa.initVerify(rsaPublic);
            rsa.update(person2bytes);
            boolean verifies = rsa.verify(sig);
            System.out.println("Signature verified: "+verifies);
            System.out.println();

            System.out.println("****** CERTIFICATES");
            KeyStore keyStoreWerner = KeyStore.getInstance("JKS");
            String fileName = "D:\\Downloads\\portecle-1.11\\portecle-1.11\\werner.jks";
            FileInputStream fis = new FileInputStream(fileName);
            keyStoreWerner.load(fis,"werner".toCharArray());
            fis.close();

            KeyStore keyStoreFreya = KeyStore.getInstance("JKS");
            fileName = "D:\\Downloads\\portecle-1.11\\portecle-1.11\\freya.jks";
            fis = new FileInputStream(fileName);
            keyStoreFreya.load(fis,"freya".toCharArray());
            fis.close();

            PrivateKey freyaPrivate = (PrivateKey) keyStoreFreya.getKey("Freya","freya".toCharArray());
            Certificate certFreya = (Certificate) keyStoreWerner.getCertificate("Freya");
            PublicKey freyaPublic = certFreya.getPublicKey();


            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, freyaPublic);
            byte[] encrypted = rsaCipher.doFinal("Qwerty Overlord".getBytes());
            System.out.println(Base64.getEncoder().encodeToString(encrypted));
            rsaCipher.init(Cipher.DECRYPT_MODE, freyaPrivate);
            byte[] decrypted = rsaCipher.doFinal(encrypted);
            System.out.println(new String(decrypted));


            System.out.println("****** SECURE COMMUNICATION");
            String message = "QWERTY OVERLORD";
            KeyPair Akey = keypairgen.generateKeyPair();
            KeyPair Bkey = keypairgen.generateKeyPair();
            PrivateKey Ska = Akey.getPrivate();
            PublicKey Pka = Akey.getPublic();
            PrivateKey Skb = Bkey.getPrivate();
            PublicKey Pkb = Bkey.getPublic();
            Key Ka = keygen.generateKey();


            Signature rsaSigner = Signature.getInstance("SHA256withRSA");
            rsaSigner.initSign(Ska);
            rsaSigner.update(message.getBytes());
            byte[] signature = rsaSigner.sign();

            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, Ka);
            byte[] encryptedSignature = aesCipher.doFinal(signature);
            byte[] encryptedMessage = aesCipher.doFinal(message.getBytes());
            System.out.println(Base64.getEncoder().encodeToString(encryptedSignature));
            rsaCipher.init(Cipher.ENCRYPT_MODE, Pkb);

            byte[] encryptedKey = rsaCipher.doFinal(Ka.getEncoded());

            //BERICHT DOORSTUREN......................

            rsaCipher.init(Cipher.DECRYPT_MODE, Skb);
            Key Kb = new SecretKeySpec(rsaCipher.doFinal(encryptedKey), "AES");
            aesCipher.init(Cipher.DECRYPT_MODE, Kb);
            byte[] decryptedMessage = aesCipher.doFinal(encryptedMessage);
            byte[] decryptedSignature = aesCipher.doFinal(encryptedSignature);
            rsaSigner.initVerify(Pka);
            rsaSigner.update(decryptedMessage);
            boolean correct = rsaSigner.verify(decryptedSignature);
            System.out.println(correct + " "+ new String(decryptedMessage));





        } catch (Exception e){
            e.printStackTrace();
        }


    }
}
