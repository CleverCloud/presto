/*
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
package com.facebook.presto.server.security;

import com.facebook.airlift.configuration.Config;

import javax.validation.constraints.NotNull;

public class BiscuitConfig
{
    private String publicRootKey;
    private String sealingKey;

    @NotNull
    public String getPublicRootKey()
    {
        return publicRootKey;
    }

    @Config("http.authentication.biscuit.public-root-key")
    public BiscuitConfig setPublicRootKey(String publicRootKey)
    {
        this.publicRootKey = publicRootKey;
        return this;
    }

    @NotNull
    public String getSealingKey()
    {
        return sealingKey;
    }

    @Config("http.authentication.biscuit.sealing-key")
    public BiscuitConfig setSealingKey(String sealingKey)
    {
        this.sealingKey = sealingKey;
        return this;
    }
}
