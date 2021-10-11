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
 * 有限域上的椭圆曲线
 */
public abstract class ECOverGF {

    /**
     * O点,即无穷远点
     */
    public static final ECPoint INFINITY = new ECPoint(null, null) {
        @Override
        public String toString() {
            return "INFINITY";
        }
    };

    /**
     * p + q
     */
    public abstract ECPoint add(ECPoint p, ECPoint q);

    /**
     * p * n
     */
    public ECPoint multiply(ECPoint p, BigInteger n) {
        ECPoint rst = INFINITY;
        ECPoint added = p;
        for (int i = 0; i < n.bitLength(); i++) {
            if (n.testBit(i)) {
                rst = add(rst, added);
            }
            added = add(added, added);
        }
        return rst;
    }

    /**
     * 验证椭圆曲线是否符合要求
     */
    public abstract void checkCurve();

    /**
     * 验证点 P 是否属于椭圆曲线
     */
    public abstract void checkPoint(ECPoint p);

    public boolean isInfinity(ECPoint p) {
        return p == INFINITY;
    }
}
