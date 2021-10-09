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
import com.github.black.crypto.digests.SM2;
import com.github.black.crypto.digests.SM3;
import com.github.black.crypto.util.Hex;
import com.github.black.crypto.util.KeyPair;
import com.github.black.crypto.util.Signature;
import com.github.black.ec.ECOverPF;
import com.github.black.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class SM2Test {

    private byte[] getId() {
        return "ALICE123@YAHOO.COM".getBytes(StandardCharsets.US_ASCII);
    }

    private byte[] getEntl(byte[] id) {
        int len = id.length * 8;
        byte[] entl = new byte[2];
        entl[0] = (byte) (len >> 8 & 255);
        entl[1] = (byte) (len & 255);
        return entl;
    }


    private void assertHexEquals(String hex, byte[] bytes) {
        Assert.assertEquals(hex.toUpperCase(Locale.ROOT), Hex.encodeHex(bytes).toUpperCase(Locale.ROOT));
    }

    /**
     * http://www.gmbz.org.cn/main/viewfile/20180108023346264349.html
     * <p>
     * A.1
     */
    @Test
    public void part1() {
        byte[] id = getId();
        assertHexEquals("414C494345313233405941484F4F2E434F4D", id);
        assertHexEquals("0090", getEntl(id));
    }

    /**
     * http://www.gmbz.org.cn/main/viewfile/20180108023346264349.html
     * <p>
     * A.2
     */
    @Test
    public void part2() {
        ECOverPF curve = new ECOverPF(
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
                new BigInteger("1", 16)
        );
        // 待签名消息 m
        byte[] m = "message digest".getBytes(StandardCharsets.US_ASCII);
        assertHexEquals("6D65737361676520646967657374", m);
        // 私钥 d
        BigInteger d = new BigInteger("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263", 16);
        // 公钥 p
        BigInteger xa = new BigInteger("0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A", 16);
        BigInteger ya = new BigInteger("7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857", 16);
        ECPoint pa = new ECPoint(xa, ya);
        curve.checkPoint(pa);
        // Z
        SM3 sm3 = new SM3();
        byte[] id = getId();
        sm3.update(getEntl(id));
        sm3.update(id);
        sm3.update(curve.getA().toByteArray());
        sm3.update(curve.getB().toByteArray());
        sm3.update(curve.getG().getX().toByteArray());
        sm3.update(curve.getG().getY().toByteArray());
        sm3.update(xa.toByteArray());
        sm3.update(ya.toByteArray());
        byte[] z = sm3.digest();
        assertHexEquals("F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A", z);
        // e
        SM3 sm3e = new SM3();
        sm3e.update(z);
        sm3e.update(m);
        byte[] e = sm3e.digest();
        assertHexEquals("B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76", e);
        BigInteger ei = new BigInteger(1, e);
        // random k
        BigInteger k = new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16);
        // 椭圆曲线点 (x1,y1)
        ECPoint p = curve.multiplyG(k);
        assertHexEquals("110FCDA57615705D5E7B9324AC4B856D23E6D9188B2AE47759514657CE25D112", p.getX().toByteArray());
        assertHexEquals("1C65D68A4A08601DF24B431E0CAB4EBE084772B3817E85811A8510B2DF7ECA1A", p.getY().toByteArray());
        // 签名 r
        BigInteger r = (ei.add(p.getX()).mod(curve.getN()));
        assertHexEquals("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1", r.toByteArray());
        // 签名 s
        BigInteger s = d.add(BigInteger.ONE).modInverse(curve.getN()).multiply(k.subtract(r.multiply(d))).mod(curve.getN());
        assertHexEquals("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7", s.toByteArray());
        // 验证签名
        assertHexEquals("B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76", e);
        BigInteger t = r.add(s).mod(curve.getN());
        assertHexEquals("2B75F07ED7ECE7CCC1C8986B991F441AD324D6D619FE06DD63ED32E0C997C801", t.toByteArray());
        // 椭圆曲线点 (x0',y0')
        p = curve.multiplyG(s);
        assertHexEquals("7DEACE5FD121BC385A3C6317249F413D28C17291A60DFD83B835A45392D22B0A", p.getX().toByteArray());
        assertHexEquals("2E49D5E5279E5FA91E71FD8F693A64A3C4A9461115A4FC9D79F34EDC8BDDEBD0", p.getY().toByteArray());
        // 椭圆曲线点 (x00',y00')
        p = curve.multiply(pa, t);
        assertHexEquals("1657FA75BF2ADCDC3C1F6CF05AB7B45E04D3ACBE8E4085CFA669CB2564F17A9F", p.getX().toByteArray());
        assertHexEquals("19F0115F21E16D2F5C3A485F8575A128BBCDDF80296A62F6AC2EB842DD058E50", p.getY().toByteArray());
        // 椭圆曲线点 (x1',y1')
        p = curve.add(curve.multiplyG(s), p);
        assertHexEquals("110FCDA57615705D5E7B9324AC4B856D23E6D9188B2AE47759514657CE25D112", p.getX().toByteArray());
        assertHexEquals("1C65D68A4A08601DF24B431E0CAB4EBE084772B3817E85811A8510B2DF7ECA1A", p.getY().toByteArray());
        BigInteger R = ei.add(p.getX()).mod(curve.getN());
        Assert.assertEquals(r, R);
    }

    @Test
    public void testECDHE() {
        SM2 sm2 = new SM2();
        // 用户
        byte[] id = getId();
        // 消息
        byte[] msg = "Hello!".getBytes(StandardCharsets.UTF_8);
        // 秘钥对
        KeyPair p = sm2.generateKeyPair();
        // 签名
        Signature s = sm2.sign(p, id, msg);
        // 验证签名
        Assert.assertTrue(sm2.verify(p.getPublicKey(), s, id, msg));
        Assert.assertFalse(sm2.verify(p.getPublicKey(), s, id, "Hi there!".getBytes(StandardCharsets.UTF_8)));
        Assert.assertFalse(sm2.verify(p.getPublicKey(), s, "other".getBytes(StandardCharsets.UTF_8), msg));
    }
}
