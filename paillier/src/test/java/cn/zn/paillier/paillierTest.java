package cn.zn.paillier;

import junit.framework.TestCase;
import cn.zn.paillier.Paillier;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Public key signature test.
 */
public class paillierTest extends TestCase {
    private Paillier paillier;


    private void processTest() {
        BigInteger[][] massege1 = {{new BigInteger("20"), new BigInteger("12")}, {new BigInteger("12"), new BigInteger("20")}};

        System.out.println("========================================");
        System.out.println("Test paillier functionality");

        BigInteger[][] em1 = paillier.Encryption(massege1);
        for (int i = 0; i< em1.length; i++){
            for (int j = 0; j < em1[i].length; j++){
                System.out.println(em1[i][j]);
            }
        }
        System.out.println("========================================");
        System.out.println("Test Decode");

        BigInteger[][] dm1 = paillier.Decryption(em1);
        for (int i = 0; i< dm1.length; i++){
            for (int j = 0; j < dm1[i].length; j++){
                System.out.println(dm1[i][j].toString());
            }
        }

        System.out.println("========================================");
        System.out.println("Test Mod 256");
        BigInteger[][] mmod1 = paillier.encodeMod(em1, new BigInteger("256"));
        for (int i = 0; i< mmod1.length; i++){
            for (int j = 0; j < mmod1[i].length; j++){
                System.out.println(mmod1[i][j].toString());
            }
        }

        System.out.println("========================================");
        System.out.println("同态测试");

        BigInteger emmul = paillier.cipher_mul(em1[0][0], em1[0][1]);
        System.out.println(emmul.toString());
        System.out.println(paillier.Decryption(emmul).toString());

    }

    public void testPaillier() {
        this.paillier = new Paillier();
        this.processTest();
    }

}
