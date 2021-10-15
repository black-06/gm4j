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

/**
 * 转换十六进制字符串
 */
public class Hex {

    /**
     * 用于建立十六进制字符的输出的字符数组
     */
    private static final char[] DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * 将字节数组转换为十六进制字符串.
     * 且十六进制字符串的长度(toCharArray().length)是字节数组的 2 倍
     *
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    public static String encodeHex(byte[] bytes) {
        final int l = bytes.length;
        final char[] out = new char[l << 1];
        // 十六进制值中的两个字符
        for (int i = 0, j = 0; i < bytes.length; i++) {
            out[j++] = DIGITS[(0xF0 & bytes[i]) >>> 4];
            out[j++] = DIGITS[0x0F & bytes[i]];
        }
        return new String(out);
    }

    /**
     * 将十六进制字符串转换为字节数组
     *
     * @param hexData 十六进制字符串
     * @return 字节数组
     */
    public static byte[] decodeHex(String hexData) {
        int len = hexData.length();
        if ((len & 0x01) != 0) {
            hexData = "0" + hexData;
            len = hexData.length();
        }
        final byte[] out = new byte[len >> 1];
        char[] data = hexData.toCharArray();
        for (int i = 0, j = 0; j < len; i++) {
            int f = Character.digit(data[j], 16) << 4;
            j++;
            f = f | Character.digit(data[j], 16);
            j++;
            out[i] = (byte) (f & 0xFF);
        }
        return out;
    }

}
