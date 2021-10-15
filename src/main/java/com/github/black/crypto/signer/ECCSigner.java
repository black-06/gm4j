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

import com.github.black.crypto.algorithm.ECC;
import com.github.black.crypto.algorithm.ECPoint;
import com.github.black.crypto.util.Hex;
import com.github.black.crypto.util.RandomUtil;

import java.math.BigInteger;

public class ECCSigner {

    private final ECC ecc;

    public ECCSigner(ECC ecc) {
        this.ecc = ecc;
    }

    /**
     * 将消息散列
     */
    private BigInteger hash(String msg) {
        BigInteger e = new BigInteger(Hex.decodeHex(msg));
        return e.shiftRight(e.bitLength() - this.ecc.getN().bitLength());
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param privateKey 私钥
     * @param msg        消息
     * @return 签名信息
     */
    public Signature sign(BigInteger privateKey, String msg) {
        BigInteger z = hash(msg);
        BigInteger n = this.ecc.getN();
        // 随机数 k
        BigInteger k, r, s;
        do {
            k = RandomUtil.secureRandomBigDecimal(this.ecc.getN());
            // r,s 即签名
            r = this.ecc.multiplyG(k).getX().mod(n);
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
        BigInteger n = this.ecc.getN();
        // 验证签名
        BigInteger smi = s.getS().modInverse(n);
        BigInteger u1 = smi.multiply(this.hash(msg)).mod(n);
        BigInteger u2 = smi.multiply(s.getR()).mod(n);
        ECPoint P = this.ecc.add(this.ecc.multiplyG(u1), this.ecc.multiply(publicKey, u2));
        return P.getX().mod(n).equals(s.getR());
    }
}
