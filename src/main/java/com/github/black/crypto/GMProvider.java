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

import com.github.black.crypto.digests.SM3;

import java.security.Provider;

/**
 * 国密 Provider
 */
public class GMProvider extends Provider {

    public GMProvider() {
        super("GM", 1.0, "GM Security Provider v1.0 By Mr.Black");
        String SM3 = SM3.class.getName();
        super.put("MessageDigest.SM3", SM3);
        super.put("Alg.Alias.MessageDigest.1.2.156.10197.1.401", SM3);
    }
}
