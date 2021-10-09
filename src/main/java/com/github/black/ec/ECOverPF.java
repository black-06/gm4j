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

package com.github.black.ec;

import java.math.BigInteger;

/**
 * 素域 <code>F<sub>p</sub></code>上的椭圆曲线: y ^ 2 = x ^ 3 + a * x + b mod p
 */
public class ECOverPF extends ECOverGF {

    private static final BigInteger B2 = BigInteger.valueOf(2);
    private static final BigInteger B3 = BigInteger.valueOf(3);
    private static final BigInteger B4 = BigInteger.valueOf(3);
    private static final BigInteger B27 = BigInteger.valueOf(27);
    private static final BigInteger MIN_P = BigInteger.valueOf(2).pow(191);

    private final BigInteger a;
    private final BigInteger b;
    private final BigInteger p;

    private final ECPoint g;
    private final BigInteger n;

    private final BigInteger h;

    /**
     * 构造一个椭圆曲线方程
     *
     * @param a  椭圆曲线方程参数 a
     * @param b  椭圆曲线方程参数 b
     * @param p  素域范围 p
     * @param gx 基点 g 的 x 坐标
     * @param gy 基点 g 的 y 坐标
     * @param n  子群的阶 n
     * @param h  子群的辅助因子 h
     */
    public ECOverPF(BigInteger a, BigInteger b, BigInteger p, BigInteger gx, BigInteger gy, BigInteger n, BigInteger h) {
        this.a = a;
        this.b = b;
        this.p = p;
        this.g = new ECPoint(gx, gy);
        this.n = n;
        this.h = h;
    }

    /**
     * p + q
     */
    @Override
    public ECPoint add(ECPoint p, ECPoint q) {
        // q 为 0,则 p + 0 = p
        if (p == INFINITY) {
            return q;
        }
        if (q == INFINITY) {
            return p;
        }
        // 斜率
        BigInteger m;
        if (p.getX().equals(q.getX())) {
            if (p.getY().negate().mod(this.getP()).equals(q.getY())) {
                return INFINITY;
            }
            // q = p,则斜率 m = ((3 * px ^ 2  + a) * (2 * py) ^ -1) mod p
            m = p.getX().pow(2).multiply(B3).add(this.getA()).multiply(p.getY().multiply(B2).modInverse(this.getP())).mod(this.getP());
        } else {
            // ((py - qy) * (px - qx) ^ -1) mod p
            m = p.getY().subtract(q.getY()).multiply(p.getX().subtract(q.getX()).modInverse(this.getP())).mod(this.getP());
        }
        // (m ^ 2 - px - qx) mod p
        BigInteger rx = m.pow(2).subtract(p.getX()).subtract(q.getX()).mod(this.getP());
        // (py + m * (rx - px)) mod p
        BigInteger ry = p.getY().add(rx.subtract(p.getX()).multiply(m)).mod(this.getP());
        return new ECPoint(rx, ry.negate().mod(this.getP()));
    }

    public ECPoint multiplyG(BigInteger n) {
        return this.multiply(this.getG(), n);
    }

    @Override
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
     * 椭圆曲线方程参数 a
     */
    public BigInteger getA() {
        return a;
    }

    /**
     * 椭圆曲线方程参数 b
     */
    public BigInteger getB() {
        return b;
    }

    /**
     * 素域范围 p
     */
    public BigInteger getP() {
        return p;
    }

    /**
     * 基点(生成元) g :用于生成子群
     */
    public ECPoint getG() {
        return g;
    }

    /**
     * 子群的阶 n
     */
    public BigInteger getN() {
        return n;
    }

    /**
     * 验证点 P 是否属于椭圆曲线
     */
    @Override
    public void checkPoint(ECPoint p) {
        if (p == INFINITY) {
            return;
        }
        // y ^ 2 = x ^ 3 + a * x + b mod p
        if (p.getY().pow(2).mod(this.getP()).equals(p.getX().pow(3).add(this.getA().multiply(p.getX())).add(this.getB()).mod(this.getP()))) {
            if (multiply(p, this.getN()) == INFINITY) {
                return;
            }
        }
        throw new IllegalArgumentException("P Not on the curve: " + p);
    }
}
