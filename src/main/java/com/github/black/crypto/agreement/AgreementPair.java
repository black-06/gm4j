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

/**
 * 协商信息对
 */
public class AgreementPair {

    /**
     * 校验信息
     */
    private final byte[] s;
    /**
     * 协商得到的对称加密秘钥,不应对外暴露.
     */
    private final byte[] privateSymmetricKey;

    public AgreementPair(byte[] s, byte[] privateSymmetricKey) {
        this.s = s;
        this.privateSymmetricKey = privateSymmetricKey;
    }

    public byte[] getS() {
        return s;
    }

    public byte[] getPrivateSymmetricKey() {
        return privateSymmetricKey;
    }
}
