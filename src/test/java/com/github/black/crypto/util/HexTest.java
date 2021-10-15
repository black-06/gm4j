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

public class HexTest {

    @Test
    public void test() {
        String str = "hello,hex";
        byte[] data = str.getBytes(StandardCharsets.UTF_8);

        String encode = Hex.encodeHex(data);
        byte[] decode = Hex.decodeHex(encode);

        Assert.assertEquals(str, new String(decode, StandardCharsets.UTF_8));
        Assert.assertEquals(data.length * 2, encode.toCharArray().length);
    }
}
