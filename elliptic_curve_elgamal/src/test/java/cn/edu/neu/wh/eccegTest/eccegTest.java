package cn.edu.neu.wh.eccegTest;

import junit.framework.TestCase;
import cn.edu.neu.wh.ECCEG.Ecc;
import cn.edu.neu.wh.ECCEG.Constant;
import cn.edu.neu.wh.ECCEG.Pair;
import cn.edu.neu.wh.ECCEG.Point;

import java.math.BigInteger;
import java.util.ArrayList;

public class eccegTest extends TestCase {
    private Ecc ecc;


    private void processTest() {
        //BigInteger[][] massege1 = {{new int(20), new BigInteger("12")}, {new BigInteger("12"), new BigInteger("20")}};
        int massege1 = 22;
        int massege2 = 12;

        System.out.println("========================================");
        System.out.println("ECCEG key generation");

        Pair<Point, Integer> key = Constant.getKey();
        System.out.println("the public key   : " + key.first);
        System.out.println("the private key  : " + key.second);

        System.out.println("========================================");
        System.out.println("Encrypt Test");

        Pair<Point, Point> cipher1 = ecc.encrypt(massege1, key.first);
        System.out.println(cipher1.first.x + " " + cipher1.first.y + " " + cipher1.second.x + " " + cipher1.second.y);

        System.out.println("========================================");
        System.out.println("Test Decode");

        int demassege1;
        demassege1 = ecc.decrypt(cipher1, key.second);
        System.out.println("解密：" + demassege1);

        System.out.println("========================================");
        System.out.println("Encrypt Test 2");

        Pair<Point, Point> cipher2 = ecc.encrypt(massege2, key.first);
        System.out.println(cipher2.first.x + " " + cipher2.first.y + " " + cipher2.second.x + " " + cipher2.second.y);

        System.out.println("========================================");
        System.out.println("Decode Test 2");

        int demassege2;
        demassege1 = ecc.decrypt(cipher2, key.second);
        System.out.println("解密：" + demassege1);

/*

        System.out.println("========================================");
        System.out.println("Test Mod 256");
        BigInteger[][] mmod1 = paillier.encodeMod(em1, new BigInteger("256"));
        for (int i = 0; i< mmod1.length; i++){
            for (int j = 0; j < mmod1[i].length; j++){
                System.out.println(mmod1[i][j].toString());
            }
        }
*/
        System.out.println("========================================");
        System.out.println("同态测试");
        Pair<Point, Point> ttest = ecc.cipher_add(cipher1,cipher2);
        System.out.println(ttest.first.x + " " + ttest.first.y + " " + ttest.second.x + " " + ttest.second.y);
        System.out.println("同态解密20+12："+ ecc.decrypt(ttest, key.second));


    }

    public void testPaillier() {
        this.ecc = new Ecc();
        this.processTest();
    }

}
