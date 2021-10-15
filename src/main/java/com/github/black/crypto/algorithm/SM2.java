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

package com.github.black.crypto.algorithm;

import com.github.black.crypto.digests.SM3Digest;
import com.github.black.crypto.util.PackUtil;
import com.github.black.crypto.util.RandomUtil;

import java.math.BigInteger;

/**
 * GM/T 0003-2012 SM2 椭圆曲线公钥密码算法.
 * 中文 PDF1 总则        http://www.gmbz.org.cn/main/viewfile/20180108015515787986.html
 * 中文 PDF4 公钥加密算法 http://www.gmbz.org.cn/main/viewfile/20180108023602687857.html
 * 中文 PDF5 参数定义    http://www.gmbz.org.cn/main/viewfile/2018010802371372251.html
 * <p>
 * Implementation of chinese public key cryptographic algorithm sm2 Based on Elliptic Curves as described at
 * https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02.
 */
public class SM2 extends ECC {

    /**
     * PDF5.2 参数定义
     */
    public static final SM2 SPEC = new SM2(
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16),
            new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16),
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16),
            new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
            new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16),
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16),
            new BigInteger("1", 16)
    );

    /**
     * 缓存 z 计算中用到的 byte array,避免重复计算
     */
    private final byte[] arrayA;
    private final byte[] arrayB;
    private final byte[] arrayGX;
    private final byte[] arrayGY;

    /**
     * 构造一个基于有限域上的椭圆曲线的加密算法
     *
     * @param a  椭圆曲线方程参数 a
     * @param b  椭圆曲线方程参数 b
     * @param p  素域范围 p
     * @param gx 基点 g 的 x 坐标
     * @param gy 基点 g 的 y 坐标
     * @param n  子群的阶 n
     * @param h  子群的辅助因子 h
     */
    public SM2(BigInteger a, BigInteger b, BigInteger p, BigInteger gx, BigInteger gy, BigInteger n, BigInteger h) {
        super(a, b, p, gx, gy, n, h);
        this.arrayA = a.toByteArray();
        this.arrayB = b.toByteArray();
        this.arrayGX = gx.toByteArray();
        this.arrayGY = gy.toByteArray();
    }

    /**
     * 根据用户标识生成秘钥对
     *
     * @param id 用户标识
     * @return 秘钥对
     */
    public SM2KeyPair generateKeyPair(byte[] id) {
        BigInteger privateKey = RandomUtil.secureRandomBigDecimal(this.getN());
        ECPoint publicKey = this.multiplyG(privateKey);
        byte[] z = this.generateZ(id, publicKey);
        return new SM2KeyPair(privateKey, publicKey, id, z);
    }

    /**
     * 5.5.用户其他信息
     *
     * @param id        用户的可辨别标识
     * @param publicKey 公钥
     * @return 用户标识信息
     */
    public byte[] generateZ(byte[] id, ECPoint publicKey) {
        SM3Digest sm3 = new SM3Digest();
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
     * 5.4.3. 秘钥派生函数
     *
     * @param k  要获得的密钥数据的长度
     * @param zs 比特串 Z
     * @return 密钥数据
     */
    public byte[] kdf(int k, byte[]... zs) {
        byte[] rst = new byte[k];
        SM3Digest sm3 = new SM3Digest();
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
}
