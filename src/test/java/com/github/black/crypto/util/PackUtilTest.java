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

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class PackUtilTest {

    @Test
    public void testBigEndianToInt() {
        byte[] bytes = "abcd".getBytes(StandardCharsets.UTF_8);
        int i = PackUtil.bigEndianToInt(bytes, 0);
        Assert.assertEquals(1633837924, i);
        Assert.assertEquals("61626364", Integer.toHexString(i));
    }

    @Test
    public void testIntToBigEndian() {
        byte[] bytes = new byte[4];
        PackUtil.intToBigEndian(1633837924, bytes, 0);
        Assert.assertEquals("abcd", new String(bytes));
    }

    private static final String data1 = "test_array_1_to_connect_";
    private static final String data2 = ",hello;";
    private static final String data3 = "??? what is up ?";

    @Test
    public void testConnect0() {
        Assert.assertArrayEquals(new byte[0], PackUtil.connect(new byte[0], null, null, new byte[0]));
    }

    @Test
    public void testConnect1() {
        byte[] rst = PackUtil.connect(
                data1.getBytes(StandardCharsets.UTF_8),
                data2.getBytes(StandardCharsets.UTF_8),
                data3.getBytes(StandardCharsets.UTF_8)
        );
        Assert.assertNotNull(rst);
        Assert.assertEquals(data1 + data2 + data3, new String(rst, StandardCharsets.UTF_8));
    }

    @Test
    public void testConnect2() {
        byte[] rst = PackUtil.connect(
                null,
                data1.getBytes(StandardCharsets.UTF_8),
                new byte[0],
                data2.getBytes(StandardCharsets.UTF_8),
                data3.getBytes(StandardCharsets.UTF_8),
                null
        );
        Assert.assertEquals(data1 + data2 + data3, new String(rst, StandardCharsets.UTF_8));
    }
}
