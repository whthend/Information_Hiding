package cn.edu.neu.wh.ecc;

import org.bouncycastle.math.ec.ECCurve;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.math.BigInteger;


public class DitiECC {
    private ECC ecc;
    private BigInteger p = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16);

    public DitiECC() throws Exception {
        this.ecc = new ECC();
        ecc.KeyGen();
        System.out.println("椭圆曲线参数a = " + this.p);
        System.out.println("椭圆曲线参数a = " + this.ecc.getKeyPairInfo().getA().toBigInteger());
        System.out.println("椭圆曲线参数b = " + this.ecc.getKeyPairInfo().getB().toBigInteger());
//        System.out.println("椭圆曲线参数q = " + ((ECCurve.Fp) this.ecc.getKeyPairInfo()).getQ());
//        p = ((ECCurve.Fp) ecc.getKeyPairInfo()).getQ();
    }

    public BigInteger Encryption(BigInteger message) throws Exception {
        byte[] m = message.toByteArray();
        return new BigInteger(this.ecc.EnCode(m));

    }

    public BigInteger[][] Encryption(BigInteger[][] message) throws Exception {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。

        BigInteger[][] encodeMassege = new  BigInteger[message.length][message[0].length];
        int row_num = message.length;
        int column_num = message[0].length;
        byte[] m;

        for (int i = 0; i < row_num; i++){
            for(int j = 0; j < column_num; j++){
                m = message[i][j].toByteArray();
//                System.out.println(new HexBinaryAdapter().marshal(this.ecc.EnCode(m)));
                encodeMassege[i][j] = new BigInteger(this.ecc.EnCode(m));
            }
        }

        return encodeMassege;


    }

    public int[][] encodeMod(BigInteger message[][]){
        int[][] modMassege = new int[message.length][message[0].length];
        BigInteger modnumber = new BigInteger("256");
        int row_num = message.length;
        int column_num = message[0].length;

        for (int i = 0; i < row_num; i++){
            for(int j = 0; j < column_num; j++){
                modMassege[i][j] = message[i][j].mod(modnumber).intValue();
            }
        }

        return modMassege;
    }


    public BigInteger Decryption(BigInteger c) throws Exception {
        byte[] m = c.toByteArray();
        return new BigInteger(this.ecc.DeCode(m));
    }

    public BigInteger[][] Decryption(BigInteger message[][]) throws Exception {
        int row_num = message.length;
        int column_num = message[0].length;
        byte[] m;
        BigInteger decodeMassege[][] = new BigInteger[message.length][message[0].length];


        for (int i = 0; i < row_num; i++){
            for(int j = 0; j < column_num; j++){
                if (message[i][j]==null){
                    decodeMassege[i][j] = new BigInteger("0");
                    continue;
                }
                m = message[i][j].toByteArray();
                decodeMassege[i][j] = new BigInteger(this.ecc.DeCode(m));
            }
        }
        return decodeMassege;
    }

    /**
     *
     * */
    public BigInteger[][] PicChange(BigInteger message[][], BigInteger s, int count){
        int row_num = message.length;
        int column_num = message[0].length;
        int m = 1;
        int column_max = message[0].length / 3;
        BigInteger mtemp;
        for(int i = 0; i < count;i++){
            for (int n = 1;n < column_num-1;n = n + 3){
                mtemp = cipher_add(message[m][n], s);

                message[m - 1][n - 1] = mtemp;
                message[m - 1][n] = mtemp;
                message[m - 1][n + 1] = mtemp;
                message[m][n - 1] = mtemp;
                message[m][n + 1] = mtemp;
                message[m + 1][n - 1] = mtemp;
                message[m + 1][n] = mtemp;
                message[m + 1][n + 1] = mtemp;
            }
            m = m + 3;
        }

        return message;
    }

    public BigInteger[][] rePicChange(BigInteger massege[][], int count){
        int row_num = massege.length;
        int column_num = massege[0].length;
        int m = 1;
        int column_max = massege[0].length / 3;
        BigInteger[][] mtemp = new BigInteger[count * 3][massege[0].length];
        for(int i = 0; i < count;i++){
            for (int n = 1;n < column_num-1;n = n + 3){

                mtemp[m - 1][n - 1] = cipher_sub(massege[m - 1][n - 1], massege[m][n]);
                mtemp[m - 1][n - 1] = cipher_sub(massege[m - 1][n - 1], massege[m][n]);
                mtemp[m - 1][n] = cipher_sub(massege[m - 1][n], massege[m][n]);
                mtemp[m - 1][n + 1] = cipher_sub(massege[m - 1][n + 1], massege[m][n]);
                mtemp[m][n - 1] = cipher_sub(massege[m][n - 1], massege[m][n]);
                mtemp[m][n + 1] = cipher_sub(massege[m][n + 1], massege[m][n]);
                mtemp[m + 1][n - 1] = cipher_sub(massege[m + 1][n - 1], massege[m][n]);
                mtemp[m + 1][n] = cipher_sub(massege[m + 1][n], massege[m][n]);
                mtemp[m + 1][n + 1] = cipher_sub(massege[m + 1][n + 1], massege[m][n]);
            }
            m = m + 3;
        }

        return mtemp;
    }


    /**
     * 两个密文的和
     * @param em1
     * @param em2
     * @return
     */

    public BigInteger cipher_add(BigInteger em1, BigInteger em2) {
        return em1.add(em2);
    }

    /**
     * 两个密文的除
     * @param em1
     * @param em2
     * @return
     */
    public BigInteger cipher_sub(BigInteger em1, BigInteger em2) {

        return em1.subtract(em2);
    }

    public BigInteger[][] InttoBig(int[][] m){
        BigInteger[][] result = new BigInteger[m.length][m[0].length];
        for (int i = 0; i < m.length; i++){
            for(int j = 0; j < m[0].length; j++){
                result[i][j] = new BigInteger(String.valueOf(m[i][j]));
            }
        }
        return result;
    }

    public BigInteger InttoBig(int m){
        BigInteger result = new BigInteger(String.valueOf(m));
        return result;
    }

    public int[][] BigtoInt(BigInteger[][] m){
        int[][] result = new int[m.length][m[0].length];
        for (int i = 0; i < m.length; i++){
            for(int j = 0; j < m[0].length; j++){
                result[i][j] = m[i][j].intValue();
            }
        }
        return result;
    }

    public int BigtoInt(BigInteger m){
        int result = m.intValue();
        return result;
    }

}
