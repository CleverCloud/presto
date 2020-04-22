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

import cafe.cryptography.curve25519.InvalidEncodingException;
import com.clevercloud.biscuit.crypto.PublicKey;
import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import com.facebook.presto.spi.security.BasicPrincipal;
import io.vavr.control.Either;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import static com.google.common.base.Strings.nullToEmpty;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static java.util.Objects.requireNonNull;

public class BiscuitAuthenticator
        implements Authenticator
{
    private final String sealingKey;
    private final PublicKey publicRootKey;

    @Inject
    public BiscuitAuthenticator(BiscuitConfig config) throws IOException
    {
        requireNonNull(config, "config is null");
        this.sealingKey = config.getSealingKey();
        try {
            this.publicRootKey = new PublicKey(hexStringToByteArray(config.getPublicRootKey()));
        }
        catch (InvalidEncodingException e) {
            throw new IOException("Unable to load publickey", e);
        }
    }

    @Override
    public Principal authenticate(HttpServletRequest request) throws AuthenticationException
    {
        String biscuit = getBiscuit(request);
        return new BasicPrincipal(parseBiscuit(biscuit));
    }

    public static String getBiscuit(HttpServletRequest request) throws AuthenticationException
    {
        String header = nullToEmpty(request.getHeader(AUTHORIZATION));

        int space = header.indexOf(' ');
        if ((space < 0) || !header.substring(0, space).equalsIgnoreCase("biscuit")) {
            throw needAuthentication(null);
        }
        String biscuit = header.substring(space + 1).trim();
        if (biscuit.isEmpty()) {
            throw needAuthentication(null);
        }

        return validateBiscuit(biscuit);
    }

    private static String validateBiscuit(final String biscuit) throws AuthenticationException
    {
        requireNonNull(biscuit);
        if (!biscuit.isEmpty()) {
            return biscuit;
        }
        else {
            throw new AuthenticationException("Blank biscuit found");
        }
    }

    private String parseBiscuit(final String biscuit) throws AuthenticationException
    {
        Either<Error, Biscuit> deser = Biscuit.from_bytes(Base64.getUrlDecoder().decode(biscuit));

        if (deser.isLeft()) {
            throw new AuthenticationException("Could not deserialize biscuit");
        }
        else {
            Biscuit realBiscuit = deser.get();

            if (realBiscuit.check_root_key(this.publicRootKey).isLeft()) {
                throw new AuthenticationException("This biscuit was not generated with the expected root key");
            }

            byte[] sealed = realBiscuit.seal(this.sealingKey.getBytes()).get();

            return "biscuit:" + Base64.getEncoder().encodeToString(sealed);
        }
    }

    private static AuthenticationException needAuthentication(String message)
    {
        return new AuthenticationException(message, "Biscuit realm=\"Presto\", token_type=\"BISCUIT\"");
    }

    private static byte[] hexStringToByteArray(String hex)
    {
        int l = hex.length();
        byte[] data = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) +
                    Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
