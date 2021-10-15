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

package com.github.black.crypto.signer;

import com.github.black.crypto.GMUtil;
import com.github.black.crypto.algorithm.ECPoint;
import com.github.black.crypto.algorithm.SM2;
import com.github.black.crypto.algorithm.SM2KeyPair;
import com.github.black.crypto.util.RandomUtil;

import java.math.BigInteger;

/**
 * 中文 PDF2 数字签名算法 http://www.gmbz.org.cn/main/viewfile/20180108023346264349.html
 */
public class SM2Signer {

    private final SM2 sm2;

    public SM2Signer(SM2 sm2) {
        this.sm2 = sm2;
    }

    /**
     * 6.数字签名的生成
     *
     * @param keyPair 用户秘钥对
     * @param msg     消息
     * @return 签名信息
     */
    public Signature sign(SM2KeyPair keyPair, byte[] msg) {
        BigInteger n = this.sm2.getN();
        BigInteger d = keyPair.getPrivateKey();
        // A1 A2
        BigInteger e = new BigInteger(1, GMUtil.sm3(keyPair.getZ(), msg));
        BigInteger r, s;
        do {
            BigInteger k;
            do {
                // A3
                k = RandomUtil.secureRandomBigDecimal(n);
                // A4 椭圆曲线点 (x1, y1)
                ECPoint p = this.sm2.multiplyG(k);
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
     * @param z         签名用户信息
     * @param signature 签名信息
     * @param msg       消息
     * @return 签名是否有效
     */
    public boolean verify(ECPoint publicKey, byte[] z, Signature signature, byte[] msg) {
        BigInteger r = signature.getR();
        BigInteger s = signature.getS();
        BigInteger n = this.sm2.getN();
        // B1
        if (r.compareTo(BigInteger.ZERO) < 1 || r.compareTo(n) > -1) {
            return false;
        }
        // B2
        if (s.compareTo(BigInteger.ZERO) < 1 || s.compareTo(n) > -1) {
            return false;
        }
        // B3 B4
        BigInteger e = new BigInteger(1, GMUtil.sm3(z, msg));
        // B5
        BigInteger t = r.add(s).mod(n);
        if (t.equals(BigInteger.ZERO)) {
            return false;
        }
        // B6 椭圆曲线点 (x1', y1')
        ECPoint p = this.sm2.add(this.sm2.multiplyG(s), this.sm2.multiply(publicKey, t));
        // B7
        BigInteger expectedR = p.getX().add(e).mod(n);
        return expectedR.equals(r);
    }
}
