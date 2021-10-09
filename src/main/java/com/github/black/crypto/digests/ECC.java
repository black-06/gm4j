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

/**
 * 基于有限域上的椭圆曲线的加密算法
 */
public class ECC {

    private final ECOverPF curve;

    /**
     * 构造
     *
     * @param a  椭圆曲线方程参数 a
     * @param b  椭圆曲线方程参数 b
     * @param p  素域范围 p
     * @param gx 基点 g 的 x 坐标
     * @param gy 基点 g 的 y 坐标
     * @param n  子群的阶 n
     * @param h  子群的辅助因子 h
     */
    public ECC(BigInteger a, BigInteger b, BigInteger p, BigInteger gx, BigInteger gy, BigInteger n, BigInteger h) {
        this.curve = new ECOverPF(a, b, p, gx, gy, n, h);
        this.curve.checkCurve();
    }

    /**
     * 将消息散列
     */
    private BigInteger hash(String msg) {
        BigInteger e = new BigInteger(Hex.decodeHex(msg));
        return e.shiftRight(e.bitLength() - this.curve.getN().bitLength());
    }

    /**
     * 生成公钥
     *
     * @return 公钥
     */
    public BigInteger generatePrivateKey() {
        return RandomUtil.randomBigDecimal(this.curve.getN());
    }

    /**
     * 使用私钥生成公钥
     *
     * @param privateKey 私钥
     * @return 公钥
     */
    public ECPoint generatePublicKey(BigInteger privateKey) {
        ECPoint publicKey = this.curve.multiplyG(privateKey);
        this.curve.checkPoint(publicKey);
        return publicKey;
    }

    /**
     * 生成一对秘钥
     *
     * @return 秘钥对
     */
    public KeyPair generateKeyPair() {
        BigInteger privateKey = this.generatePrivateKey();
        ECPoint publicKey = this.generatePublicKey(privateKey);
        return new KeyPair(privateKey, publicKey);
    }

    /**
     * 生成对称秘钥
     *
     * @param otherPublicKey 对方的公钥
     * @param privateKey     私钥
     * @return 对称秘钥
     */
    public ECPoint generateSymmetricKey(ECPoint otherPublicKey, BigInteger privateKey) {
        return this.curve.multiply(otherPublicKey, privateKey);
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param privateKey 私钥
     * @param msg        消息
     * @return 签名信息
     */
    public Signature sign(BigInteger privateKey, String msg) {
        BigInteger z = this.hash(msg);
        BigInteger n = this.curve.getN();
        // 随机数 k
        BigInteger k, r, s;
        do {
            k = RandomUtil.randomBigDecimal(this.curve.getN());
            // r,s 即签名
            r = this.curve.multiplyG(k).getX().mod(n);
            s = k.modInverse(n).multiply(r.multiply(privateKey).add(z)).mod(n);
        } while (r.equals(BigInteger.ZERO) && s.equals(BigInteger.ZERO));
        return new Signature(r, s);
    }

    /**
     * 校验签名
     *
     * @param publicKey 公钥
     * @param s         签名信息
     * @param msg       待校验的消息
     * @return 签名是否有效
     */
    public boolean verify(ECPoint publicKey, Signature s, String msg) {
        // 验证签名
        BigInteger smi = s.getS().modInverse(this.curve.getN());
        BigInteger u1 = smi.multiply(this.hash(msg)).mod(this.curve.getN());
        BigInteger u2 = smi.multiply(s.getR()).mod(this.curve.getN());
        ECPoint P = this.curve.add(this.curve.multiplyG(u1), this.curve.multiply(publicKey, u2));
        return P.getX().mod(this.curve.getN()).equals(s.getR());
    }
}
