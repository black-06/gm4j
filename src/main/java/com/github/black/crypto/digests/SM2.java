/*
 * Copyright 2021 hello.bug@foxmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.black.crypto.digests;

import com.github.black.crypto.util.Hex;
import com.github.black.crypto.util.KeyPair;
import com.github.black.crypto.util.RandomUtil;
import com.github.black.crypto.util.Signature;
import com.github.black.ec.ECOverPF;
import com.github.black.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class SM2 extends MessageDigest {

    private static final byte[] ID = "1234567812345678".getBytes(StandardCharsets.UTF_8);
    private static final ECOverPF CURVE = new ECOverPF(
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16),
            new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16),
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16),
            new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
            new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16),
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16),
            new BigInteger("1", 16));

    private final ECOverPF curve;
    private final byte[] arrayA;
    private final byte[] arrayB;
    private final byte[] arrayGX;
    private final byte[] arrayGY;

    private final byte[] id;
    private final KeyPair keyPair;

    /**
     * 按照 SM2 给定参数构造
     */
    public SM2() {
        this(CURVE, null, null);
    }

    public SM2(byte[] id, KeyPair keyPair) {
        this(CURVE, id, keyPair);
    }

    /**
     * 构造
     *
     * @param a       椭圆曲线方程参数 a
     * @param b       椭圆曲线方程参数 b
     * @param p       素域范围 p
     * @param gx      基点 g 的 x 坐标
     * @param gy      基点 g 的 y 坐标
     * @param n       子群的阶 n
     * @param id      用户标识
     * @param keyPair 用户秘钥对
     */
    public SM2(BigInteger a, BigInteger b, BigInteger p, BigInteger gx, BigInteger gy, BigInteger n, BigInteger h, byte[] id, KeyPair keyPair) {
        this(new ECOverPF(a, b, p, gx, gy, n, h), id, keyPair);
    }


    public SM2(ECOverPF curve, byte[] id, KeyPair keyPair) {
        super("MessageDigest.SM2");
        this.curve = curve;
        this.curve.checkCurve();
        this.arrayA = curve.getA().toByteArray();
        this.arrayB = curve.getB().toByteArray();
        this.arrayGX = curve.getG().getX().toByteArray();
        this.arrayGY = curve.getG().getY().toByteArray();
        this.id = id == null ? ID : id;
        this.keyPair = keyPair == null ? generateKeyPair() : keyPair;
    }

    @Override
    protected void engineUpdate(byte input) {

    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {

    }

    @Override
    protected byte[] engineDigest() {
        return new byte[0];
    }

    @Override
    protected void engineReset() {

    }

    /**
     * 5.5.用户其他信息
     *
     * @param id        用户的可辨别标识
     * @param publicKey 公钥
     * @return 用户标识信息
     */
    private byte[] Z(byte[] id, ECPoint publicKey) {
        SM3 sm3 = new SM3();
        // ENTL
        int len = id.length * 8;
        sm3.update((byte) (len >> 8 & 255));
        sm3.update((byte) (len & 255));
        // ID
        sm3.update(id);
        // curve
        sm3.update(arrayA);
        sm3.update(arrayB);
        sm3.update(arrayGX);
        sm3.update(arrayGY);
        // 公钥
        sm3.update(publicKey.getX().toByteArray());
        sm3.update(publicKey.getY().toByteArray());
        return sm3.digest();
    }

    public BigInteger generatePrivateKey() {
        return RandomUtil.randomBigDecimal(curve.getN());
    }

    public ECPoint generatePublicKey(BigInteger privateKey) {
        ECPoint publicKey = curve.multiplyG(privateKey);
        curve.checkPoint(publicKey);
        return publicKey;
    }

    public KeyPair generateKeyPair() {
        BigInteger privateKey = generatePrivateKey();
        ECPoint publicKey = generatePublicKey(privateKey);
        return new KeyPair(privateKey, publicKey);
    }

    public ECPoint generateSymmetricKey(ECPoint otherPublicKey, BigInteger privateKey) {
        return curve.multiply(otherPublicKey, privateKey);
    }

    public byte[] getId() {
        return id;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     * 6.数字签名的生成
     *
     * @param keyPair 用户秘钥对
     * @param id      用户标识
     * @param msg     消息
     * @return 签名信息
     */
    public Signature sign(KeyPair keyPair, byte[] id, byte[] msg) {
        BigInteger n = curve.getN();
        BigInteger d = keyPair.getPrivateKey();
        byte[] z = Z(id, keyPair.getPublicKey());
        // A1 A2
        SM3 sm3 = new SM3();
        sm3.update(z);
        sm3.update(msg);
        BigInteger e = new BigInteger(Hex.encodeHex(sm3.digest()), 16);
        BigInteger r, s;
        do {
            BigInteger k;
            do {
                // A3
                k = RandomUtil.randomBigDecimal(n);
                // A4 椭圆曲线点 (x1, y1)
                ECPoint p = curve.multiplyG(k);
                // A5
                r = e.add(p.getX()).mod(n);
            } while (r.equals(BigInteger.ZERO) || r.add(k).equals(n));
            // A6
            s = d.add(BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(d))).mod(n);
        } while (s.equals(BigInteger.ZERO));
        return new Signature(r, s);
    }

    /**
     * 7.数字签名的认证
     *
     * @param publicKey 公钥
     * @param signature 签名信息
     * @param msg       消息
     * @return 签名是否有效
     */
    public boolean verify(ECPoint publicKey, Signature signature, byte[] id, byte[] msg) {
        BigInteger r = signature.getR();
        BigInteger s = signature.getS();
        BigInteger n = this.curve.getN();
        // B1
        if (r.compareTo(BigInteger.ZERO) < 1 || r.compareTo(n) > -1) {
            return false;
        }
        // B2
        if (s.compareTo(BigInteger.ZERO) < 1 || s.compareTo(n) > -1) {
            return false;
        }
        // B3 B4
        byte[] z = Z(id, publicKey);
        SM3 sm3 = new SM3();
        sm3.update(z);
        sm3.update(msg);
        BigInteger e = new BigInteger(1, sm3.digest());
        // B5
        BigInteger t = r.add(s).mod(n);
        if (t.equals(BigInteger.ZERO)) {
            return false;
        }
        // B6 椭圆曲线点 (x1', y1')
        ECPoint p = curve.add(curve.multiplyG(s), curve.multiply(publicKey, t));
        // B7
        BigInteger expectedR = p.getX().add(e).mod(n);
        return expectedR.equals(r);
    }
}
