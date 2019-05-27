package cn.zn.paillier;
/**
 * 密钥生成：
 * 1、随机选择两个大质数p和q满足gcd（pq,(p-1)(q-1)）=1。 这个属性是保证两个质数长度相等。
 * 2、计算 n = pq和λ= lcm (p - 1,q-1)。
 * 3、选择随机整数g使得gcd(L(g^lambda % n^2) , n) = 1,满足g属于n^2;
 * 4、公钥为（N，g）
 * 5、私钥为lambda。
 * :加密
 * 选择随机数r满足
 * 计算密文
 * 其中m为加密信息
 *
 * 解密：
 * m = D(c,lambda) = ( L(c^lambda%n^2)/L(g^lambda%n^2) )%n;
 * 其中L(u) = (u-1)/n;
 */

import java.math.*;
import java.util.*;

public class Paillier {

    //p,q是两个随机的质数， lambda = lcm(p-1, q-1);
    private BigInteger p, q, lambda;

    // n = p*q
    public BigInteger n;

    // nsquare就是n的平方
    public BigInteger nsquare;
    /**
     * 随机选取一个整数 g,g属于小于n的平方中的整数集,且 g 满足:g的lambda次方对n的平方求模后减一后再除与n，
     * 最后再将其与n求最大公约数，且最大公约数等于一。
     * a random integer in Z*_{n^2} where gcd (L(g^lambda mod nsquare), n) = 1.
     */
    private BigInteger g;
    //bitLength 模量
    private int bitLength;

    /**
     * Constructs an instance of the Paillier cryptosystem.
     *
     * @param bitLengthVal
     *            number of bits of modulus 模量
     * @param certainty
     *            The probability that the new BigInteger represents a prime
     *            number will exceed (1 - 2^(-certainty)). The execution time of
     *            this constructor is proportional to the value of this
     *            parameter.
     *带参的构造方法
     */
    public Paillier(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    /**
     * Constructs an instance of the Paillier cryptosystem with 512 bits of
     * modulus and at least 1-2^(-64) certainty of primes generation.
     * 构造方法
     */
    public Paillier() {
        KeyGeneration(512, 64);
    }

    /**
     * 产生公钥【N,g】       私钥lamada
     * @param bitLengthVal
     *            number of bits of modulus.
     * @param certainty
     *            certainty - 调用方允许的不确定性的度量。
     *            新的 BigInteger 表示素数的概率超出 (1 - 1/2certainty)。
     *            此构造方法的执行时间与此参数的值是成比例的。
     */
    public void KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        //构造两个随机生成的正 大质数，长度可能为bitLength/2，它可能是一个具有指定 bitLength 的素数
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());

        //n = p*q;
        n = p.multiply(q);
        //nsquare = n*n;
        nsquare = n.multiply(n);
        //随机生成一个0~100的整数g
        g = new BigInteger( String.valueOf( (int) (  Math.random()*100 ) ));

        //lamada=lcm(p-1,q-1),即lamada是p-1,q-1的最小公倍数
        //lamada=((p-1)*(q-1)) / gcd(p-1,q-1);
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))  //(p-1)*(q-1)
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
        //检验g是否符合公式的要求， gcd (L(g^lambda mod nsquare), n) = 1.
        if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
            System.out.println("g is not good. Choose g again.");
            System.exit(1);
        }
    }

    /**
     * @param m 明文m
     * @param r 随机的一个整数r
     * @return 返回密文
     * 加密
     */
    public BigInteger Encryption(BigInteger m, BigInteger r) {
        //c = (g^m)*(r^n)modnsquare
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    public BigInteger Encryption(BigInteger m) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

    }

    public BigInteger[][] Encryption(BigInteger[][] massege) {
        //构造一个随机生成的 BigInteger，它是在 0 到 (2numBits - 1)（包括）范围内均匀分布的值。

        BigInteger[][] encodeMassege = new  BigInteger[massege.length][massege[0].length];
        int row_num = massege.length;
        int column_num = massege[0].length;
//        BigInteger mtemp = g.modPow(massege[0][0], nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
//        System.out.println(mtemp);
        for (int i = 0; i < row_num; i++){
            for(int j = 0; j < column_num; j++){
                BigInteger r = new BigInteger(bitLength, new Random());
                encodeMassege[i][j] = g.modPow(massege[i][j], nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
            }
        }
        return encodeMassege;

    }

    public BigInteger[][] encodeMod(BigInteger massege[][], BigInteger modnumber){
        BigInteger[][] modMassege = new BigInteger[massege.length][massege[0].length];
        int row_num = massege.length;
        int column_num = massege[0].length;

        for (int i = 0; i < row_num; i++){
            for(int j = 0; j < column_num; j++){
                modMassege[i][j] = massege[i][j].mod(modnumber);
            }
        }

        return modMassege;
    }


    /**
     * 利用私钥lamada对密文c进行解密返回明文m
     * 公式：m = ( L((c^lambda) mod nsquare) / L((g^lambda) mod nsquare) ) mod n
     */
    public BigInteger Decryption(BigInteger c) {
        BigInteger u1 = c.modPow(lambda, nsquare);
        BigInteger u2 = g.modPow(lambda, nsquare);
        return (u1.subtract(BigInteger.ONE).divide(n)).multiply(u2.subtract(BigInteger.ONE).divide(n).modInverse(n)).mod(n);
    }

    public BigInteger[][] Decryption(BigInteger massege[][]) {
        int row_num = massege.length;
        int column_num = massege[0].length;
        BigInteger decodeMassege[][] = new BigInteger[massege.length][massege[0].length];
        BigInteger u1;
        BigInteger u2 = g.modPow(lambda, nsquare);
        for (int i = 0; i < row_num; i++){
            for(int j = 0; j < column_num; j++){
                u1 = massege[i][j].modPow(lambda, nsquare);
                decodeMassege[i][j] = (u1.subtract(BigInteger.ONE).divide(n)).multiply(u2.subtract(BigInteger.ONE).divide(n).modInverse(n)).mod(n);
            }
        }
        return decodeMassege;
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
     * 两个密文的乘
     * @param em1
     * @param em2
     * @return
     */
    public BigInteger cipher_mul(BigInteger em1, BigInteger em2) {
        return em1.multiply(em2).mod(nsquare);
    }
}
