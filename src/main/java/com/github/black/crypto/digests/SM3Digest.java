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

import com.github.black.crypto.util.PackUtil;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * GM/T 0004-2012 SM3 密码杂凑算法.
 * 中文 PDF http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html
 * <p>
 * Implementation of Chinese SM3 cryptographic hash algorithm as described at
 * https://tools.ietf.org/html/draft-shen-sm3-hash-01
 *
 * <pre>{@code
 * 4.1.初始值 / Initial Value:
 *      IV 7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e
 * 4.2.常量 / Constants:
 *      Tj = 79cc4519   when  0 <= j <= 15
 *      Tj = 7a879d8a   when 16 <= j <= 63
 * 4.3.布尔函数 / Boolean Function:
 *      FFj(X;Y;Z) = X XOR Y XOR Z                          when  0 <= j <= 15
 *      FFj(X;Y;Z) = (X AND Y) OR (X AND Z) OR (Y AND Z)    when 16 <= j <= 63
 *      GGj(X;Y;Z) = X XOR Y XOR Z                          when  0 <= j <= 15
 *      GGj(X;Y;Z) = (X AND Y) OR (NOT X AND Z)             when 16 <= j <= 63
 *      式中 X,Y,Z 为字. The X in the formula are a word.
 * 4.4.置换函数 / Permutation Function:
 *      P0(X) = X XOR (X rotateLeft  9) XOR (X rotateLeft 17)
 *      P1(X) = X XOR (X rotateLeft 15) XOR (X rotateLeft 23)
 *      式中 X,Y,Z 为字. The X in the formula are a word.
 *
 * }</pre>
 */
public class SM3Digest extends MessageDigest {

    /**
     * 4.1.初始值
     */
    private static final int[] IV = new int[8];

    /**
     * 4.2.常量 (提前计算为 5.3.3 的 Tj rotateLeft (j mod 32))
     */
    private static final int[] T = new int[64];

    static {
        IV[0] = 0x7380166F;
        IV[1] = 0x4914B2B9;
        IV[2] = 0x172442D7;
        IV[3] = 0xDA8A0600;
        IV[4] = 0xA96F30BC;
        IV[5] = 0x163138AA;
        IV[6] = 0xE38DEE4D;
        IV[7] = 0xB0FB0E4E;
        for (int j = 0; j < 16; j++) {
            T[j] = Integer.rotateLeft(0x79CC4519, j);
        }
        for (int j = 16; j < 64; j++) {
            T[j] = Integer.rotateLeft(0x7A879D8A, j % 32);
        }
    }

    private static int FF0(int x, int y, int z) {
        return x ^ y ^ z;
    }

    private static int FF1(int x, int y, int z) {
        return (x & y) | (x & z) | (y & z);
    }

    private static int GG0(int x, int y, int z) {
        return x ^ y ^ z;
    }

    private static int GG1(int x, int y, int z) {
        return (x & y) | (~x & z);
    }

    private static int P0(int x) {
        return x ^ Integer.rotateLeft(x, 9) ^ Integer.rotateLeft(x, 17);

    }

    private static int P1(int x) {
        return x ^ Integer.rotateLeft(x, 15) ^ Integer.rotateLeft(x, 23);
    }

    /**
     * 一个分组 512 bit,即 64 个 byte,即 16 个 int.
     */
    private static final int GROUP_SIZE = 16;
    /**
     * 存储一个分组
     */
    private int[] group;
    private int groupOffset;

    private static final int BUFF_SIZE = 4;
    /**
     * 尚未转换为 int 的缓存,可以存储 4 个比特,即 32 个 bit
     */
    private byte[] buff;
    private int buffOffset;

    /**
     * 消息总长度,64位
     */
    private long len;

    private int[] vi;

    public SM3Digest() {
        super("MessageDigest.SM3");
        engineReset();
    }

    /**
     * 5.3.3.压缩函数
     */
    private void CF() {
        /*
         * 5.3.2.消息扩展
         */
        int[] w = new int[68];
        // a
        System.arraycopy(this.group, 0, w, 0, 16);
        // b
        for (int j = 16; j < 68; j++) {
            w[j] = P1(w[j - 16] ^ w[j - 9] ^ Integer.rotateLeft(w[j - 3], 15))
                    ^ Integer.rotateLeft(w[j - 13], 7)
                    ^ w[j - 6];
        }
        /*
         * 5.3.3.压缩函数
         */
        int a = this.vi[0];
        int b = this.vi[1];
        int c = this.vi[2];
        int d = this.vi[3];
        int e = this.vi[4];
        int f = this.vi[5];
        int g = this.vi[6];
        int h = this.vi[7];
        for (int j = 0; j < 16; j++) {
            int a12 = Integer.rotateLeft(a, 12);
            int ss1 = Integer.rotateLeft(a12 + e + T[j], 7);
            int ss2 = ss1 ^ a12;
            // c
            int w1j = w[j] ^ w[j + 4];
            int tt1 = FF0(a, b, c) + d + ss2 + w1j;
            int tt2 = GG0(e, f, g) + h + ss1 + w[j];
            d = c;
            c = Integer.rotateLeft(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = Integer.rotateLeft(f, 19);
            f = e;
            e = P0(tt2);
        }
        for (int j = 16; j < 64; j++) {
            int a12 = Integer.rotateLeft(a, 12);
            int ss1 = Integer.rotateLeft(a12 + e + T[j], 7);
            int ss2 = ss1 ^ a12;
            // c
            int w1j = w[j] ^ w[j + 4];
            int tt1 = FF1(a, b, c) + d + ss2 + w1j;
            int tt2 = GG1(e, f, g) + h + ss1 + w[j];
            d = c;
            c = Integer.rotateLeft(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = Integer.rotateLeft(f, 19);
            f = e;
            e = P0(tt2);
        }
        this.vi[0] ^= a;
        this.vi[1] ^= b;
        this.vi[2] ^= c;
        this.vi[3] ^= d;
        this.vi[4] ^= e;
        this.vi[5] ^= f;
        this.vi[6] ^= g;
        this.vi[7] ^= h;
    }

    /**
     * 5.2.填充
     */
    private void fill() {
        this.write((byte) 128);
        // 填充 0 直到 group 剩余 2 位
        while (this.buffOffset != 0) {
            this.write((byte) 0);
        }
        while (this.groupOffset != GROUP_SIZE - 2) {
            this.group[this.groupOffset++] = 0;
        }
        // 存储数据总长度
        this.len *= 8;
        this.group[this.groupOffset++] = (int) (this.len >>> 32);
        this.group[this.groupOffset++] = (int) this.len;
    }


    /**
     * 将字节写入 4 字节缓冲区,
     * 当缓冲区满时,将其打包为 int 存入 16 整形组中,
     * 当整形组满时,将其压缩至 vi
     *
     * @param input 用于更新的字节
     */
    private void write(byte input) {
        this.buff[this.buffOffset++] = input;
        if (this.buffOffset == BUFF_SIZE) {
            this.group[this.groupOffset++] = PackUtil.bigEndianToInt(this.buff, 0);
            this.buffOffset = 0;
            if (this.groupOffset == GROUP_SIZE) {
                CF();
                this.groupOffset = 0;
            }
        }
    }

    /**
     * 重置 MessageDigest 以供下一次使用
     */
    @Override
    protected void engineReset() {
        this.group = new int[GROUP_SIZE];
        this.groupOffset = 0;
        this.buff = new byte[BUFF_SIZE];
        this.buffOffset = 0;
        this.len = 0;
        this.vi = Arrays.copyOf(IV, IV.length);
    }

    /**
     * 使用指定的字节更新 MessageDigest
     *
     * @param input 用于更新的字节
     */
    @Override
    protected void engineUpdate(byte input) {
        this.len++;
        this.write(input);
    }

    /**
     * 使用指定的字节数组更新 MessageDigest,从指定的偏移量开始。
     *
     * @param input  用于更新的字节数组
     * @param offset 指定的偏移量
     * @param len    使用的字节数量,从偏移量开始
     */
    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        len = Math.max(0, len);
        this.len += len;
        for (int i = offset; i < len; i++) {
            this.write(input[i]);
        }
    }

    /**
     * 通过执行填充等最终操作来完成哈希计算.并完成重置
     *
     * @return 结果哈希值
     */
    @Override
    protected byte[] engineDigest() {
        fill();
        CF();
        byte[] rst = new byte[32];
        int offset = 0;
        for (int v : vi) {
            PackUtil.intToBigEndian(v, rst, offset);
            offset += 4;
        }
        reset();
        return rst;
    }
}
