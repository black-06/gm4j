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

import com.github.black.crypto.digests.SM3;
import com.github.black.crypto.util.Hex;

import java.nio.charset.StandardCharsets;

/**
 * 国密的静态工具类
 */
public class GMUtil {

    private static byte[] getBytes(String str) {
        return str.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] sm3(byte[] bytes) {
        return new SM3().digest(bytes);
    }

    public static byte[] sm3(String str) {
        return sm3(getBytes(str));
    }

    public static String sm3Hex(byte[] bytes) {
        return Hex.encodeHex(sm3(bytes));
    }

    public static String sm3Hex(String str) {
        return sm3Hex(getBytes(str));
    }
}
