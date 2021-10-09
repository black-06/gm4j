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

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class ECOverPFTest {

    @Test
    public void testMultiply() {
        BigInteger[] is = new BigInteger[98];
        for (int i = 0; i < is.length; i++) {
            is[i] = BigInteger.valueOf(i);
        }

        ECOverGF ec = new ECOverPF(is[2], is[3], is[97], null, null, is[5], null);

        ECPoint p = new ECPoint(is[3], is[6]);

        ECPoint r;

        r = ec.multiply(p, BigInteger.valueOf(151));
        Assert.assertEquals(r, new ECPoint(is[3], is[6]));
        ec.checkPoint(r);

        r = ec.multiply(p, is[2]);
        Assert.assertEquals(r, new ECPoint(is[80], is[10]));
        ec.checkPoint(r);

        r = ec.multiply(p, is[3]);
        Assert.assertEquals(r, new ECPoint(is[80], is[87]));
        ec.checkPoint(r);

        r = ec.multiply(p, is[4]);
        Assert.assertEquals(r, new ECPoint(is[3], is[91]));
        ec.checkPoint(r);

        r = ec.multiply(p, is[5]);
        Assert.assertEquals(r, ECOverGF.INFINITY);
        ec.checkPoint(r);

        r = ec.multiply(p, is[6]);
        Assert.assertEquals(r, new ECPoint(is[3], is[6]));
        ec.checkPoint(r);

        r = ec.multiply(p, is[7]);
        Assert.assertEquals(r, new ECPoint(is[80], is[10]));
        ec.checkPoint(r);
    }

}
