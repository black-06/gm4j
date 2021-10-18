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
import java.util.Arrays;

public class SM2Digest extends MessageDigest {

    private final SM2 sm2;

    private ECCKeyPair keyPair;
    private byte[] data;
    private int size;

    public SM2Digest() {
        this(SM2.SPEC, null);
    }

    private SM2Digest(SM2 sm2, ECCKeyPair keyPair) {
        super("MessageDigest.SM2");
        this.keyPair = keyPair == null ? sm2.generateKeyPair() : keyPair;
        // A3
        ECPoint s = sm2.multiply(this.keyPair.getPublicKey(), sm2.getN());
        if (s.isInfinity()) {
            throw new IllegalArgumentException();
        }
        this.sm2 = sm2;
        this.keyPair = keyPair;
        this.engineReset();
    }

    public void resize(int minCapacity) {
        int oldCapacity = data.length;
        int newCapacity = oldCapacity + (oldCapacity >> 1);
        if (newCapacity < minCapacity) {
            newCapacity = minCapacity;
        }
        // 谨防溢出
        if (newCapacity < 0) {
            throw new OutOfMemoryError();
        }
        // minCapacity is usually close to size, so this is a win:
        this.data = Arrays.copyOf(this.data, newCapacity);
    }

    @Override
    protected void engineUpdate(byte input) {
        resize(this.size + 1);
        this.data[this.size++] = input;
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        resize(this.size + len);
        System.arraycopy(input, offset, this.data, this.size, len);
    }

    /**
     * PDF4.6 加密算法及流程
     *
     * @return 加密后的消息
     */
    @Override
    protected byte[] engineDigest() {
        while (true) {
            // A1
            BigInteger k = RandomUtil.secureRandomBigDecimal(this.sm2.getN());
            // A4: [k]PB = (x2,y2)
            ECPoint p = this.sm2.multiply(this.keyPair.getPublicKey(), k);
            byte[] x2 = p.getX().toByteArray();
            byte[] y2 = p.getY().toByteArray();
            /*
             * A5: t = KDF(x2 ∥ y2, k), 若 t 全 0 则返回 A1.
             * A6: t 与 m 依次进行异或计算.
             * 当 t 全 0 时, t 与 m 异或结果仍为 m.
             */
            byte[] c2 = this.kdfWithXor(this.data, x2, y2);
            // 检查异或结果
            for (int i = 0; i < c2.length; i++) {
                if (c2[i] != this.data[i]) {
                    // A2
                    byte[] c1 = this.sm2.serializePoint(this.sm2.multiplyG(k), false);
                    byte[] c3 = GMUtil.sm3(x2, this.data, y2);
                    return PackUtil.connect(c1, c2, c3);
                }
            }
        }
    }

    public byte[] decrypt() {
        // TODO: 解密
        return null;
    }

    /**
     * 重置 MessageDigest 以供下一次使用
     */
    @Override
    protected void engineReset() {
        this.data = new byte[10];
        this.size = 0;
    }

    private byte[] kdfWithXor(byte[] msg, byte[]... zs) {
        byte[] rst = new byte[this.size];
        SM3Digest sm3 = new SM3Digest();
        int ct = 0, offset = 0;
        byte[] buff = new byte[4];
        while (offset < this.size) {
            sm3.reset();
            for (byte[] z : zs) {
                sm3.update(z);
            }
            PackUtil.intToBigEndian(++ct, buff, 0);
            sm3.update(buff);
            byte[] digest = sm3.digest();
            int len = Math.min(32, this.size - offset);
            // xor
            for (int i = 0; i < len; i++) {
                int p = offset + i;
                rst[p] = (byte) (msg[p] ^ digest[i]);
            }
            offset += len;
        }
        return rst;
    }

    public ECCKeyPair getKeyPair() {
        return keyPair;
    }
}
