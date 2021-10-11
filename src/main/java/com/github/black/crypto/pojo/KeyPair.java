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

package com.github.black.crypto.pojo;

import com.github.black.ec.ECPoint;

import java.math.BigInteger;

/**
 * 秘钥对
 */
public class KeyPair {

    private final BigInteger privateKey;
    private final ECPoint publicKey;

    public KeyPair(BigInteger privateKey, ECPoint publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }
}
