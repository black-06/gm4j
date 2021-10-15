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

import com.github.black.crypto.algorithm.ECCKeyPair;
import com.github.black.crypto.algorithm.ECPoint;
import com.github.black.crypto.algorithm.SM2;
import com.github.black.crypto.algorithm.SM2KeyPair;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class SM2AgreementTest {

    private static final byte[] ID_A = "ALICE123@YAHOO.COM".getBytes(StandardCharsets.US_ASCII);

    private static final byte[] ID_B = "BILL456@YAHOO.COM".getBytes(StandardCharsets.US_ASCII);

    private static final SM2 SM2 = new SM2(
            // a
            new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16),
            // b
            new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16),
            // p
            new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16),
            // gx
            new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16),
            // gy
            new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16),
            // n
            new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16),
            // h
            new BigInteger("1", 16)
    );

    private static final SM2Agreement agreement = new SM2Agreement(SM2);

    @Test
    public void test() throws KeyAgreementException {
        // 私钥 da
        BigInteger da = new BigInteger("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16);
        // 公钥 pa
        ECPoint pa = SM2.multiplyG(da);
        // 用户信息
        byte[] za = SM2.generateZ(ID_A, pa);
        // 秘钥对
        SM2KeyPair kpa = new SM2KeyPair(da, pa, ID_A, za);
        // 随机数 ra
        BigInteger ra = new BigInteger("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16);
        ECPoint Ra = SM2.multiplyG(ra);

        // 私钥 db
        BigInteger db = new BigInteger("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16);
        // 公钥 pb
        ECPoint pb = SM2.multiplyG(db);
        // 用户信息
        byte[] zb = SM2.generateZ(ID_B, pb);
        // 秘钥对
        SM2KeyPair kpb = new SM2KeyPair(db, pb, ID_B, zb);
        // 随机数 rb
        BigInteger rb = new BigInteger("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16);
        ECPoint Rb = SM2.multiplyG(rb);

        /*========================================= 选项 1: 请求方进行校验 s =========================================*/
        // 请求方请求
        PublicInfo initiator = new PublicInfo(true, 16, za, pa, Ra, null);
        // 响应方响应,生成对称秘钥并生成 s 返回
        AgreementPair pairB = agreement.generate(initiator, kpb, new ECCKeyPair(rb, Rb));
        PublicInfo responder = new PublicInfo(false, 16, zb, pb, Rb, pairB.getS());
        // 请求方校验,生成对称秘钥并校验 s
        AgreementPair pairA = agreement.generate(responder, kpa, new ECCKeyPair(ra, Ra));
        // 检验双方对称秘钥是否一致
        Assert.assertArrayEquals(pairA.getPrivateSymmetricKey(), pairB.getPrivateSymmetricKey());

        /*========================================= 选项 2: 响应方进行校验 s =========================================*/
        // 请求方获得公开信息
        responder = new PublicInfo(false, 16, zb, pb, Rb, null);
        // 请求方生成对称秘钥并生成 s
        pairA = agreement.generate(responder, kpa, new ECCKeyPair(ra, Ra));
        // 请求方请求
        initiator = new PublicInfo(true, 16, za, pa, Ra, pairA.getS());
        // 响应方响应,生成对称秘钥并校验 s
        pairB = agreement.generate(initiator, kpb, new ECCKeyPair(rb, Rb));
        // 检验双方对称秘钥是否一致
        Assert.assertArrayEquals(pairA.getPrivateSymmetricKey(), pairB.getPrivateSymmetricKey());
    }

}
