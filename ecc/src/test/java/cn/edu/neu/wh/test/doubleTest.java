package cn.edu.neu.wh.test;

import cn.edu.neu.wh.ecc.DitiECC;
import junit.framework.TestCase;
import cn.edu.neu.wh.ecc.DitiECC;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Public key signature test.
 */
public class doubleTest extends TestCase {
    private DitiECC ecc;


    private void processTest() {
        int[][] m = {{1,2},{3,5}};
        System.out.println("========================================");
        System.out.println("同态测试");

        BigInteger[][] emmul = ecc.InttoBig(m);
        for (int i = 0; i< emmul.length; i++){
            for (int j = 0; j < emmul[i].length; j++){
                System.out.println(emmul[i][j].toString());
            }
        }

    }

    public void testPaillier() throws Exception{
        this.ecc = new DitiECC();
        this.processTest();
    }

}
