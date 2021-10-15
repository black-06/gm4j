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

import java.security.GeneralSecurityException;

/**
 * 秘钥协商异常,当协商失败时抛出
 */
public class KeyAgreementException extends GeneralSecurityException {

    /**
     * 构造具有指定详细消息的 KeyAgreementException.
     * 详细消息是描述此特定异常的字符串.
     *
     * @param msg 详细消息
     */
    public KeyAgreementException(String msg) {
        super(msg);
    }

}
