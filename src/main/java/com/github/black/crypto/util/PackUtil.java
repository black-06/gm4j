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

public class PackUtil {

    /**
     * 将大端 byte[] 转换存储为 int.
     * 一个 int 可以存储 4 个 byte ,即 32 个 bit
     *
     * @param bytes  待转换的大端 byte[]
     * @param offset 开始读取的位置
     * @return 转换后的 int
     */
    public static int bigEndianToInt(byte[] bytes, int offset) {
        int n = bytes[offset] << 24;
        n |= (bytes[++offset] & 0xff) << 16;
        n |= (bytes[++offset] & 0xff) << 8;
        n |= (bytes[++offset] & 0xff);
        return n;
    }

    /**
     * 将 int 还原回大端 byte[],并写入给定的数组
     *
     * @param n      转换后的 int
     * @param bytes  给定的数据
     * @param offset 写入位置
     */
    public static void intToBigEndian(int n, byte[] bytes, int offset) {
        bytes[offset] = (byte) (n >>> 24);
        bytes[++offset] = (byte) (n >>> 16);
        bytes[++offset] = (byte) (n >>> 8);
        bytes[++offset] = (byte) (n);
    }

    /**
     * 将大数转换为指定长度的无符号字节数组,必要时使用前导0填充
     *
     * @param integer 要转换的大数
     * @param length  字节数组长度
     * @return 无符号字节数组
     */
    public static byte[] toUnsignedByteArray(BigInteger integer, int length) {
        byte[] bytes = integer.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        int start = (bytes[0] == 0 && bytes.length != 1) ? 1 : 0;
        int count = bytes.length - start;
        if (count > length) {
            throw new IllegalArgumentException("standard length exceeded for value");
        }
        byte[] tmp = new byte[length];
        System.arraycopy(bytes, start, tmp, tmp.length - count, count);
        return tmp;
    }
}
