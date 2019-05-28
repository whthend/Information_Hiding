package cn.edu.neu.wh.eccegTest;

import junit.framework.TestCase;
import cn.edu.neu.wh.ECCEG.Ecc;
import cn.edu.neu.wh.ECCEG.Constant;
import cn.edu.neu.wh.ECCEG.Pair;
import cn.edu.neu.wh.ECCEG.Point;

import java.math.BigInteger;

public class eccegTest extends TestCase {
    private Ecc ecc;


    private void processTest() {
        //BigInteger[][] massege1 = {{new int(20), new BigInteger("12")}, {new BigInteger("12"), new BigInteger("20")}};
        int[][] massege1 = {{20, 12}, {12, 20}};
        System.out.println("========================================");
        System.out.println("ECCEG key generation");

        Pair<Point, Integer> key = Constant.getKey();
        System.out.println("the public key   : " + key.first);
        System.out.println("the private key  : " + key.second);

        System.out.println("========================================");
        System.out.println("Test paillier functionality");

        BigInteger[][] em1 = ecc.Encryption(massege1);
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
        this.ecc = new Ecc();
        this.processTest();
    }

}
