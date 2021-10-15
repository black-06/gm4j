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

package com.github.black.crypto.agreement;

import com.github.black.crypto.algorithm.ECPoint;

/**
 * 用于协商的必要信息
 */
public class PublicInfo {
    /**
     * 是否为发起方
     */
    private final boolean initiator;
    /**
     * 协商秘钥长度
     */
    private final int k;
    /**
     * 用户其他信息
     */
    private final byte[] z;
    /**
     * 用户公钥
     */
    private final ECPoint p;
    /**
     * 随机公钥 r
     */
    private final ECPoint r;
    /**
     * 校验信息
     */
    private final byte[] s;

    public PublicInfo(boolean initiator, int k, byte[] z, ECPoint p, ECPoint r, byte[] s) {
        this.initiator = initiator;
        this.k = k;
        this.z = z;
        this.p = p;
        this.r = r;
        this.s = s;
    }

    public boolean isInitiator() {
        return initiator;
    }

    public int getK() {
        return k;
    }

    public byte[] getZ() {
        return z;
    }

    public ECPoint getP() {
        return p;
    }

    public ECPoint getR() {
        return r;
    }

    public byte[] getS() {
        return s;
    }
}
