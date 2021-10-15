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

package com.github.black.crypto.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class RandomUtil {

    private static final ThreadLocal<SecureRandom> RANDOM = new ThreadLocal<>();

    /**
     * 加密强随机生成位于 (0,n) 区间的随机数
     *
     * @param end 开区间右端点,不包含
     * @return 随机数
     */
    public static BigInteger secureRandomBigDecimal(BigInteger end) {
        return secureRandomBigDecimal(BigInteger.ZERO, end);
    }

    /**
     * 加密强随机生成位于 (start,end) 区间的随机数
     *
     * @param start 开区间左端点,不包含
     * @param end   开区间右端点,不包含
     * @return 随机数
     */
    public static BigInteger secureRandomBigDecimal(BigInteger start, BigInteger end) {
        SecureRandom random = RANDOM.get();
        if (random == null) {
            random = new SecureRandom();
            RANDOM.set(random);
        }
        return randomBigDecimal(start, end, random);
    }

    public static BigInteger randomBigDecimal(BigInteger start, BigInteger end, Random random) {
        BigInteger r;
        do {
            r = new BigInteger(end.bitLength(), random);
        } while (r.compareTo(start) < 1 || r.compareTo(end) > -1);
        return r;
    }
}
