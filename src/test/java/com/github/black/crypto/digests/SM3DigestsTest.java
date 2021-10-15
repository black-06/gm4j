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

package com.github.black.crypto.digests;

import com.github.black.crypto.GMUtil;
import com.github.black.crypto.util.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class SM3DigestsTest {

    @Test
    public void testBytes() {
        // Example1
        assertHexEquals(
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                GMUtil.sm3("abc".getBytes(StandardCharsets.US_ASCII))
        );

        // Example2
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            builder.append("abcd");
        }
        assertHexEquals(
                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
                GMUtil.sm3(builder.toString().getBytes(StandardCharsets.US_ASCII))
        );
    }

    private void assertHexEquals(String hex, byte[] bytes) {
        Assert.assertEquals(hex.toUpperCase(Locale.ROOT), Hex.encodeHex(bytes).toUpperCase(Locale.ROOT));
    }

    @Test
    public void testByte() {
        // Example1
        byte a = 'a';
        byte b = 'b';
        byte c = 'c';
        SM3Digest sm3 = new SM3Digest();
        sm3.update(a);
        sm3.update(b);
        sm3.update(c);
        assertHexEquals("66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0", sm3.digest());

        // Example2
        sm3.reset();
        byte d = 'd';
        for (int i = 0; i < 16; i++) {
            sm3.update(a);
            sm3.update(b);
            sm3.update(c);
            sm3.update(d);
        }
        assertHexEquals("DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732", sm3.digest());
    }

}
