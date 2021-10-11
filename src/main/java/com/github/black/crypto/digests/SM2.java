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

import com.github.black.crypto.GMUtil;
import com.github.black.crypto.pojo.KeyPair;
import com.github.black.crypto.pojo.Signature;
import com.github.black.crypto.util.Hex;
import com.github.black.crypto.util.PackUtil;
import com.github.black.crypto.util.RandomUtil;
import com.github.black.ec.ECOverPF;
import com.github.black.ec.ECPoint;
import com.github.black.exception.KeyAgreementException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * GM/T 0003-2012 SM2 椭圆曲线公钥密码算法.
 * 中文 PDF1 总则        http://www.gmbz.org.cn/main/viewfile/20180108015515787986.html
 * 中文 PDF2 数字签名算法 http://www.gmbz.org.cn/main/viewfile/20180108023346264349.html
 * 中文 PDF3 密钥交换协议 http://www.gmbz.org.cn/main/viewfile/20180108023456003485.html
 * 中文 PDF4 公钥加密算法 http://www.gmbz.org.cn/main/viewfile/20180108023602687857.html
 * 中文 PDF5 参数定义    http://www.gmbz.org.cn/main/viewfile/2018010802371372251.html
 * <p>
 * Implementation of chinese public key cryptographic algorithm sm2 Based on Elliptic Curves as described at
 * https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02.
 */
public class SM2 extends MessageDigest {

    private static final byte[] ID = "1234567812345678".getBytes(StandardCharsets.UTF_8);
    /**
     * PDF5.2 参数定义
     */
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

    /**
     * 按照 SM2 规范参数构造
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

    /**
     * 生成私钥
     *
     * @return 私钥
     */
    public BigInteger generatePrivateKey() {
        return RandomUtil.randomBigDecimal(curve.getN());
    }

    /**
     * 根据私钥生成公钥
     *
     * @param privateKey 私钥
     * @return 公钥
     */
    public ECPoint generatePublicKey(BigInteger privateKey) {
        ECPoint publicKey = curve.multiplyG(privateKey);
        curve.checkPoint(publicKey);
        return publicKey;
    }

    /**
     * 生成秘钥对
     *
     * @return 秘钥对
     */
    public KeyPair generateKeyPair() {
        BigInteger privateKey = generatePrivateKey();
        ECPoint publicKey = generatePublicKey(privateKey);
        return new KeyPair(privateKey, publicKey);
    }

    public byte[] keyExchange(int k, byte[] id, KeyPair b, byte[] ida, ECPoint Ra, ECPoint pa) throws KeyAgreementException {
        // B5_1: 验证 ra 是否满足椭圆曲线方程
        try {
            this.curve.checkPoint(Ra);
        } catch (IllegalArgumentException e) {
            throw new KeyAgreementException("other public key mismatch curve");
        }
        BigInteger n = this.curve.getN();
        BigInteger the_2_w = BigInteger.valueOf(2).pow((int) Math.ceil(n.bitLength() / 2.0) - 1);
        // B1: 随机数 rb ∈ [1, n-1]
        BigInteger rb = RandomUtil.randomBigDecimal(n);
        // B2: Rb = [rB]G = (x2,y2)
        ECPoint Rb = this.curve.multiplyG(rb);
        // B3: x2_
        BigInteger x2_ = the_2_w.subtract(BigInteger.ONE).and(Rb.getX()).add(the_2_w);
        // B4: tb = (dB + x2_ · rb) mod n
        BigInteger tb = x2_.multiply(rb).add(b.getPrivateKey()).mod(n);
        // B5_2: x1_
        BigInteger x1_ = the_2_w.subtract(BigInteger.ONE).and(Ra.getX()).add(the_2_w);
        // B6: v = [h · tb](pa + [x1_]ra) = (xv,yv)
        ECPoint v = this.curve.multiply(this.curve.add(this.curve.multiply(Ra, x1_), pa), CURVE.getH().multiply(tb));
        if (this.curve.isInfinity(v)) {
            throw new KeyAgreementException("V is infinity");
        }
        byte[] xv = v.getX().toByteArray();
        byte[] yv = v.getY().toByteArray();
        // kb = KDF(xv ∥ yv ∥ za ∥ zb, k)
        byte[] za = Z(ida, pa);
        byte[] zb = Z(id, b.getPublicKey());
        byte[] kb = kdf(k, xv, yv, za, zb);
        // B8: sb = hash(0x02 ∥ yv ∥ hash(xv ∥ za ∥ zb ∥ x1 ∥ y1 ∥ x2 ∥ y2))
        byte[] sb = S1(Ra, Rb, za, zb, xv, yv);
        // TODO: 分角色/分校验 按照指定格式返回
        return null;
    }

    /**
     * 5.4.3. 秘钥派生函数
     *
     * @param k  要获得的密钥数据的长度
     * @param zs 比特串 Z
     * @return 密钥数据
     */
    private byte[] kdf(int k, byte[]... zs) {
        byte[] rst = new byte[k];
        SM3 sm3 = new SM3();
        int ct = 0, offset = 0;
        byte[] buff = new byte[4];
        while (offset < k) {
            sm3.reset();
            for (byte[] z : zs) {
                sm3.update(z);
            }
            PackUtil.intToBigEndian(++ct, buff, 0);
            sm3.update(buff);
            int len = Math.min(32, k - offset);
            System.arraycopy(sm3.digest(), 0, rst, offset, len);
            offset += len;
        }
        return rst;
    }

    private byte[] S1(ECPoint Ra, ECPoint Rb, byte[] za, byte[] zb, byte[] xv, byte[] yv) {
        return GMUtil.sm3(new byte[]{2}, yv,
                GMUtil.sm3(xv, za, zb,
                        Ra.getX().toByteArray(), Ra.getY().toByteArray(),
                        Rb.getX().toByteArray(), Rb.getY().toByteArray()
                ));
    }

    private byte[] S2(ECPoint Ra, ECPoint Rb, byte[] za, byte[] zb, byte[] xv, byte[] yv) {
        return GMUtil.sm3(new byte[]{3}, yv,
                GMUtil.sm3(xv, za, zb,
                        Ra.getX().toByteArray(), Ra.getY().toByteArray(),
                        Rb.getX().toByteArray(), Rb.getY().toByteArray()
                ));
    }

    private static ECPoint calculateUV(ECPoint ra, ECPoint pa, BigInteger x1_, BigInteger tb) {
        return null;
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
