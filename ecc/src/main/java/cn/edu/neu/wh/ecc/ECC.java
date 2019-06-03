package cn.edu.neu.wh.ecc;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;


import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECC {


    private KeyPairGenerator keyPairGenerator;
    private KeyPair keyPair;
    private ECPrivateKey ecPrivateKey;
    private ECPublicKey ecPublicKey;
    private Cipher cipher;


    public ECC() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        this.cipher = Cipher.getInstance("ECIES", "BC");
    }

    public void KeyGen() throws Exception{
        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ECParameterSpec ecSpec=new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());
        this.keyPairGenerator = KeyPairGenerator.getInstance("ECIES", "BC");
        this.keyPairGenerator.initialize(ecSpec, new SecureRandom());
        this.keyPair = keyPairGenerator.generateKeyPair();
        this.ecPublicKey = (ECPublicKey) keyPair.getPublic();
        this.ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

    }

    public byte[] EnCode(byte[] message) throws Exception{

        cipher.init(Cipher.ENCRYPT_MODE, this.ecPublicKey);
        return cipher.doFinal(message);
    }

    public byte[] DeCode(byte[] message) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, this.ecPrivateKey);
        return cipher.doFinal(message);
    }

    public ECCurve getKeyPairInfo(){
//        BigInteger q = ECCurve.Fp.
        return this.ecPublicKey.getParameters().getCurve();
    }


/* public static void main(String[] args) throws Exception {
        byte[] plainText = "Hello World!".getBytes();
        byte[] cipherText = null;


        System.out.println(plainText.getClass().toString());


        //生成公钥和私钥

        //打印密钥信息
        ECCurve ecCurve = ecPublicKey.getParameters().getCurve();
        System.out.println("椭圆曲线参数a = " + ecCurve.getA().toBigInteger());
        System.out.println("椭圆曲线参数b = " + ecCurve.getB().toBigInteger());
        System.out.println("椭圆曲线参数q = " + ((ECCurve.Fp) ecCurve).getQ());
        ECPoint basePoint = ecPublicKey.getParameters().getG();
        System.out.println("基点橫坐标              "
                + basePoint.getAffineXCoord().toBigInteger());
        System.out.println("基点纵坐标              "
                + basePoint.getAffineYCoord().toBigInteger());
        System.out.println("公钥横坐标              "
                + ecPublicKey.getQ().getAffineXCoord().toBigInteger());
        System.out.println("公钥纵坐标              "
                + ecPublicKey.getQ().getAffineYCoord().toBigInteger());
        System.out.println("私钥                    " + ecPrivateKey.getD());

        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        // 加密
        cipher.init(Cipher.ENCRYPT_MODE, ecPublicKey);
        cipherText = cipher.doFinal(plainText);
        System.out.println("密文: " + new HexBinaryAdapter().marshal(cipherText));
        // 解密
        cipher.init(Cipher.DECRYPT_MODE, ecPrivateKey);
        plainText = cipher.doFinal(cipherText);
        // 打印解密后的明文
        System.out.println("解密后的明文: " + new String(plainText));
    }*/
}