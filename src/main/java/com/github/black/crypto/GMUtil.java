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

import com.github.black.crypto.digests.SM3Digest;
import com.github.black.crypto.util.Hex;

import java.nio.charset.StandardCharsets;

/**
 * 国密的静态工具类
 */
public class GMUtil {

    private static byte[] getBytes(String str) {
        return str.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * SM3杂凑算法,使用给定消息生成 32 byte(即 256 bit) 杂凑值
     *
     * @param bytes 待杂凑的消息
     * @return 32 byte[] 杂凑值
     */
    public static byte[] sm3(byte[]... bytes) {
        SM3Digest sm3 = new SM3Digest();
        for (byte[] bs : bytes) {
            sm3.update(bs);
        }
        return sm3.digest();
    }

    /**
     * SM3杂凑算法,使用给定消息生成 32 byte(即 256 bit) 杂凑值
     *
     * @param str 待杂凑的消息
     * @return 32 byte[] 杂凑值
     */
    public static byte[] sm3(String... str) {
        SM3Digest sm3 = new SM3Digest();
        for (String s : str) {
            sm3.update(getBytes(s));
        }
        return sm3.digest();
    }

    /**
     * SM3杂凑算法,使用给定消息生成 32 byte(即 256 bit) 杂凑值并转换为 16 进制的字符串(64 char)
     *
     * @param bytes 待杂凑的消息
     * @return 16 进制的杂凑值字符串(64 char)
     */
    public static String sm3Hex(byte[]... bytes) {
        return Hex.encodeHex(sm3(bytes));
    }

    /**
     * SM3杂凑算法,使用给定消息生成 32 byte(即 256 bit) 杂凑值并转换为 16 进制的字符串(64 char)
     *
     * @param str 待杂凑的消息
     * @return 16 进制的杂凑值字符串(64 char)
     */
    public static String sm3Hex(String... str) {
        return Hex.encodeHex(sm3(str));
    }
}
