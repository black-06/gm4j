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

import com.github.black.crypto.util.RandomUtil;

import java.math.BigInteger;

/**
 * 基于有限域上的椭圆曲线的加密算法
 */
public class ECC extends ECOverFP {

    /**
     * 基点(生成元) g: 循环子群的生成元/基点.
     * 定义: g 的加法是个闭环,即使将 2n 个 g 相加,得到的结果仍然与 n 个 g 相加的结果相同
     */
    private final ECPoint g;
    /**
     * 子群的阶 n,即上述关于 g 定义中的 n.
     * 即有限域中椭圆曲线的最少点数
     */
    private final BigInteger n;
    /**
     * 辅因子: 曲线点数与 G 点阶数 n 之间的关系.
     * 即曲线点数可以是 h 倍的 n.但一般为 1.
     */
    private final BigInteger h;

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
    public ECC(BigInteger a, BigInteger b, BigInteger p, BigInteger gx, BigInteger gy, BigInteger n, BigInteger h) {
        super(a, b, p);
        this.g = new ECPoint(gx, gy);
        this.n = n;
        this.h = h;
    }

    /**
     * 将给定的值与基点 g 相乘
     */
    public ECPoint multiplyG(BigInteger n) {
        return this.multiply(this.getG(), n);
    }

    @Override
    public void checkPoint(ECPoint p) {
        super.checkPoint(p);
        if (this.multiply(p, this.getN()) == ECPoint.INFINITY) {
            return;
        }
        throw new IllegalArgumentException("illegal public key: " + p);
    }


    public ECPoint getG() {
        return g;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getH() {
        return h;
    }

    /**
     * 生成一对秘钥
     *
     * @return 秘钥对
     */
    public ECCKeyPair generateKeyPair() {
        BigInteger privateKey = RandomUtil.secureRandomBigDecimal(this.getN());
        ECPoint publicKey = this.multiplyG(privateKey);
        return new ECCKeyPair(privateKey, publicKey);
    }
}
