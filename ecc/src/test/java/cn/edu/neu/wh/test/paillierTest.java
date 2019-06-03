package cn.edu.neu.wh.test;

import junit.framework.TestCase;
import cn.edu.neu.wh.ecc.DitiECC;


import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Public key signature test.
 */
public class paillierTest extends TestCase {
    private DitiECC ditiECC;


    private void processTest() throws Exception {
        int[][] testmassege = {{162,162,162}, {156,156,157}, {158,158,161}};

        BigInteger[][] massege1 = ditiECC.InttoBig(testmassege);

        System.out.println("========================================");
        System.out.println("Test ditiECC functionality");

        BigInteger[][] em1 = ditiECC.Encryption(massege1);
        for (int i = 0; i< em1.length; i++){
            for (int j = 0; j < em1[i].length; j++){

                System.out.println(em1[i][j]);
            }
        }
      System.out.println("\nEncryption is done");

        System.out.println("========================================");
        System.out.println("Test Decode");

        BigInteger[][] dm1 = ditiECC.Decryption(em1);
        for (int i = 0; i< dm1.length; i++){
            for (int j = 0; j < dm1[i].length; j++){
                System.out.println(dm1[i][j].toString());
            }
        }
      System.out.println("Decode is done");

        System.out.println("========================================");
        System.out.println("同态测试");

        BigInteger emmul = ditiECC.cipher_add(em1[0][0], em1[0][1]);
        System.out.println(emmul.toString());
        System.out.println(ditiECC.Decryption(emmul).toString());


        System.out.println("========================================");
        System.out.println("同态测试");

        BigInteger emmu2 = ditiECC.cipher_sub(emmul, em1[0][1]);
        System.out.println(emmu2.toString());
        System.out.println();
        System.out.println(ditiECC.Decryption(emmu2).toString());
        System.out.println(ditiECC.Decryption(em1[0][1]).toString());

        System.out.println("========================================");
        System.out.println("嵌入");

        BigInteger messageOne = new BigInteger("1");
        messageOne = ditiECC.Encryption(messageOne);
        BigInteger[][] messageIn = ditiECC.PicChange(em1, messageOne,1);
        BigInteger[][] messageOut = ditiECC.rePicChange(messageIn, 1);
        messageOut = ditiECC.Decryption(messageOut);

    }

    public void testPaillier() throws Exception {
        this.ditiECC = new DitiECC();
        this.processTest();
    }





}
