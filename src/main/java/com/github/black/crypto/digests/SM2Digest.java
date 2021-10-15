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
import com.github.black.crypto.algorithm.ECCKeyPair;
import com.github.black.crypto.algorithm.ECPoint;
import com.github.black.crypto.algorithm.SM2;
import com.github.black.crypto.util.PackUtil;
import com.github.black.crypto.util.RandomUtil;

import java.math.BigInteger;
import java.security.MessageDigest;

public class SM2Digest extends MessageDigest {

    private final SM2 sm2;
    private final ECPoint publicKey;

    public SM2Digest() {
        super("MessageDigest.SM2");
        this.sm2 = SM2.SPEC;
        ECCKeyPair kp = this.sm2.generateKeyPair();
        this.publicKey = kp.getPublicKey();
    }

    private SM2Digest(SM2 sm2, ECPoint publicKey) {
        super("MessageDigest.SM2");
        this.sm2 = sm2;
        this.publicKey = publicKey;
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
     * PDF4.6 加密算法及流程
     *
     * @param publicKey 公钥
     * @param msg       待加密信息
     * @return 加密后的消息
     */
    public byte[] encrypt(ECPoint publicKey, byte[] msg) {
        while (true) {
            // A1
            BigInteger k = RandomUtil.secureRandomBigDecimal(this.sm2.getN());
            // A2
            ECPoint c1p = this.sm2.multiplyG(k);
            // A3
            ECPoint s = this.sm2.multiply(publicKey, this.sm2.getN());
            // A4: [k]PB = (x2,y2)
            ECPoint p = this.sm2.multiply(publicKey, k);
            byte[] x2 = p.getX().toByteArray();
            byte[] y2 = p.getY().toByteArray();
            /*
             * A5: t = KDF(x2 ∥ y2, k), 若 t 全 0 则返回 A1.
             * A6: t 与 m 依次进行异或计算.
             * 当 t 全 0 时, t 与 m 异或结果仍为 m.
             */
            byte[] c2 = this.kdfWithXor(msg, x2, y2);
            // 检查异或结果
            for (int i = 0; i < c2.length; i++) {
                if (c2[i] != msg[i]) {
                    // TODO: Point => byte[]
                    byte[] c1 = null;
                    byte[] c3 = GMUtil.sm3(x2, msg, y2);
                    return PackUtil.connect(c1, c2, c3);
                }
            }
        }

    }

    private byte[] kdfWithXor(byte[] msg, byte[]... zs) {
        byte[] rst = new byte[msg.length];
        SM3Digest sm3 = new SM3Digest();
        int ct = 0, offset = 0;
        byte[] buff = new byte[4];
        while (offset < msg.length) {
            sm3.reset();
            for (byte[] z : zs) {
                sm3.update(z);
            }
            PackUtil.intToBigEndian(++ct, buff, 0);
            sm3.update(buff);
            byte[] digest = sm3.digest();
            int len = Math.min(32, msg.length - offset);
            // xor
            for (int i = 0; i < len; i++) {
                int p = offset + i;
                rst[p] = (byte) (msg[p] ^ digest[i]);
            }
            offset += len;
        }
        return rst;
    }
}
