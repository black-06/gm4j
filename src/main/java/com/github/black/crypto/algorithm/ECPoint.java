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
import java.util.Objects;

/**
 * 椭圆曲线上的一个点
 */
public class ECPoint {

    /**
     * O点,即无穷远点
     */
    public static final ECPoint INFINITY = new ECPoint(null, null) {
        @Override
        public String toString() {
            return "INFINITY";
        }
    };

    private final BigInteger x;
    private final BigInteger y;

    public ECPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ECPoint point = (ECPoint) o;
        return Objects.equals(getX(), point.getX()) && Objects.equals(getY(), point.getY());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getX(), getY());
    }

    @Override
    public String toString() {
        return "P( " + getX().toString(16) + " , " + getY().toString(16) + " )";
    }
}
