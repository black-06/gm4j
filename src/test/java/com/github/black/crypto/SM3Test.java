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

package com.github.black.crypto;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class SM3Test {

    @Test
    public void test() {
        // Example1
        Assert.assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                GMUtil.sm3Hex("abc".getBytes(StandardCharsets.US_ASCII)));

        // Example2
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            builder.append("abcd");
        }
        Assert.assertEquals("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
                GMUtil.sm3Hex(builder.toString().getBytes(StandardCharsets.US_ASCII)));
    }

}
