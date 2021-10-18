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

import java.math.BigInteger;

/**
 * 素域 <code>F<sub>p</sub></code>上的椭圆曲线: y ^ 2 = x ^ 3 + a * x + b mod p
 */
public class ECOverFP {

    private static final BigInteger B2 = BigInteger.valueOf(2);
    private static final BigInteger B3 = BigInteger.valueOf(3);
    private static final BigInteger B4 = BigInteger.valueOf(4);
    private static final BigInteger B27 = BigInteger.valueOf(27);
    private static final BigInteger MIN_P = BigInteger.valueOf(2).pow(191);

    /**
     * 椭圆曲线方程参数 a
     */
    private final BigInteger a;
    /**
     * 椭圆曲线方程参数 b
     */
    private final BigInteger b;
    /**
     * 素域范围 p
     */
    private final BigInteger p;

    /**
     * 构造一个椭圆曲线方程
     *
     * @param a 椭圆曲线方程参数 a
     * @param b 椭圆曲线方程参数 b
     * @param p 素域范围 p
     */
    public ECOverFP(BigInteger a, BigInteger b, BigInteger p) {
        this.a = a;
        this.b = b;
        this.p = p;
    }

    /**
     * 加法: p + q.
     * <p>
     * p + 0 = p; p + -p = 0
     * <p>
     * 当画一条直线通过 p,q 两点,那么这条线将与椭圆曲线相交于第三个点 r,
     * 再取点 r 关于 x 轴的对称点 -r ,即几何加法的 p + q 的结果.
     * <p>
     * 当 p,q 为同一点时, 该直线为 p 关于椭圆曲线的切线.
     *
     * @param p 点 p
     * @param q 点 q
     * @return -r
     */
    public ECPoint add(ECPoint p, ECPoint q) {
        // q 为 0,则 p + 0 = p
        if (p.isInfinity()) {
            return q;
        }
        if (q.isInfinity()) {
            return p;
        }
        // 斜率
        BigInteger m;
        // xp == xq
        if (p.getX().equals(q.getX())) {
            // yp == -yq 则 q 其实为 -p ,和为 p + -p =  0
            if (p.getY().negate().mod(this.getP()).equals(q.getY())) {
                return ECPoint.INFINITY;
            }
            // yp == yq 则 p q 为同一点,计算斜率 m = ((3 * px ^ 2  + a) * (2 * py) ^ -1) mod p
            m = p.getX().pow(2).multiply(B3).add(this.getA()).multiply(p.getY().multiply(B2).modInverse(this.getP())).mod(this.getP());
        } else {
            // p q 不在同一点,则计算斜率 m = ((py - qy) * (px - qx) ^ -1) mod p
            m = p.getY().subtract(q.getY()).multiply(p.getX().subtract(q.getX()).modInverse(this.getP())).mod(this.getP());
        }
        // xr = (m ^ 2 - px - qx) mod p
        BigInteger rx = m.pow(2).subtract(p.getX()).subtract(q.getX()).mod(this.getP());
        // yr = (py + m * (rx - px)) mod p
        BigInteger ry = p.getY().add(rx.subtract(p.getX()).multiply(m)).mod(this.getP());
        return new ECPoint(rx, ry.negate().mod(this.getP()));
    }

    /**
     * 乘法: p * n.
     * <p>
     * 倍加法计算.
     */
    public ECPoint multiply(ECPoint p, BigInteger n) {
        ECPoint rst = ECPoint.INFINITY;
        ECPoint added = p;
        for (int i = 0, len = n.bitLength(); i < len; i++) {
            if (n.testBit(i)) {
                rst = add(rst, added);
            }
            added = add(added, added);
        }
        return rst;
    }

    public void checkCurve() {
        // 验证参数 4 * a ^ 3 + 27 * b ^ 2 != 0
        if (this.getA().pow(3).multiply(B4).add(this.getB().pow(2).multiply(B27)).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("4 * a ^ 3 + 27 * b ^ 2 Should not be equal to 0");
        }
        // 验证 p
        if (this.getP().compareTo(MIN_P) < 0) {
            throw new IllegalArgumentException("Too small prime p,Should be greater than 2 ^ 191");
        }
    }

    /**
     * 验证点 P 是否属于椭圆曲线
     */
    public void checkPoint(ECPoint p) {
        if (p.isInfinity()) {
            return;
        }
        // y ^ 2 = x ^ 3 + a * x + b mod p
        BigInteger l = p.getY().pow(2).mod(this.getP());
        BigInteger r = p.getX().pow(3).add(this.getA().multiply(p.getX())).add(this.getB()).mod(this.getP());
        if (l.equals(r)) {
            return;
        }
        throw new IllegalArgumentException("P Not on the curve: " + p);
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getB() {
        return b;
    }

    public BigInteger getP() {
        return p;
    }
}
