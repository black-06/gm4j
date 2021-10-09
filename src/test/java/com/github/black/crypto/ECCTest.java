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

import com.github.black.crypto.digests.ECC;
import com.github.black.crypto.util.KeyPair;
import com.github.black.crypto.util.Signature;
import com.github.black.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class ECCTest {

    /**
     * SECP256K1 比特币曲线
     */
    public ECC SECP256K1() {
        return new ECC(
                new BigInteger("0"),
                new BigInteger("7"),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16),
                new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
                new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16),
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),
                new BigInteger("1")
        );
    }

    @Test
    public void testECDH() {
        ECC ecc = SECP256K1();
        // a 的秘钥对
        KeyPair a = ecc.generateKeyPair();
        // b 的秘钥对
        KeyPair b = ecc.generateKeyPair();
        // 共享秘钥 S
        ECPoint sA = ecc.generateSymmetricKey(b.getPublicKey(), a.getPrivateKey());
        ECPoint sB = ecc.generateSymmetricKey(a.getPublicKey(), b.getPrivateKey());
        Assert.assertEquals(sA, sB);
    }

    @Test
    public void testECDHE() {
        ECC ecc = SECP256K1();
        // 消息
        String msg = "Hello!";
        // 秘钥对
        KeyPair p = ecc.generateKeyPair();
        // 签名
        Signature s = ecc.sign(p.getPrivateKey(), msg);
        // 验证签名
        Assert.assertTrue(ecc.verify(p.getPublicKey(), s, msg));
        Assert.assertFalse(ecc.verify(p.getPublicKey(), s, "Hi there!"));
    }
}
