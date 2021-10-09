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
 * 二元扩域 <code>F<sub>2<sup>m</sup></sub></code>上的椭圆曲线: y ^ 2 + x * y = x ^ 3 + a * x + b
 */
public class ECOverF2m extends ECOverGF {

    final BigInteger a;

    final BigInteger b;

    public ECOverF2m(BigInteger a, BigInteger b) {
        this.a = a;
        this.b = b;
    }

    @Override
    public ECPoint add(ECPoint p, ECPoint q) {
        return null;
    }

    @Override
    public void checkCurve() {
        // 验证 b
        if (b.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("B should not be 0");
        }
    }

    @Override
    public void checkPoint(ECPoint p) {

    }
}
