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
import java.util.concurrent.ThreadLocalRandom;

public class RandomUtil {

    /**
     * 随机生成位于 (0,n) 区间的随机数
     *
     * @param end 开区间右端点,不包含
     * @return 随机数
     */
    public static BigInteger randomBigDecimal(BigInteger end) {
        return randomBigDecimal(BigInteger.ZERO, end);
    }

    /**
     * 随机生成位于 (start,end) 区间的随机数
     *
     * @param start 开区间左端点,不包含
     * @param end   开区间右端点,不包含
     * @return 随机数
     */
    public static BigInteger randomBigDecimal(BigInteger start, BigInteger end) {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        BigInteger r;
        do {
            r = new BigInteger(end.bitLength(), random);
        } while (r.compareTo(start) < 1 || r.compareTo(end) > -1);
        return r;
    }
}
