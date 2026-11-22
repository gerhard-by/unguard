/*
 * Copyright 2026 Dynatrace LLC
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

package org.dynatrace.profileservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"ADMIN_USERNAME=test-admin", "ADMIN_PASSWORD=test-password"})
class DigestAuthenticationTests {

    @LocalServerPort
    private int port;

    @Test
    void digestAuthenticationRejectsUnknownUsers() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        URI uri = URI.create("http://localhost:" + port + "/admin/stats");
        assertEquals(200, authenticate(client, uri, "test-admin", "test-password"));
        assertEquals(401, authenticate(client, uri, "test-admin", "wrong-password"));
        assertEquals(401, authenticate(client, uri, "unknown-user", "null"));
    }

    private int authenticate(HttpClient client, URI uri, String username, String password)
            throws Exception {
        HttpResponse<String> challenge = client.send(HttpRequest.newBuilder(uri).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, challenge.statusCode());
        String header = challenge.headers().firstValue("WWW-Authenticate").orElseThrow();
        String realm = challengeValue(header, "realm");
        String nonce = challengeValue(header, "nonce");
        String opaque = challengeValue(header, "opaque");
        String nc = "00000001";
        String cnonce = "test-client-nonce";
        String a1 = md5(username + ":" + realm + ":" + password);
        String a2 = md5("GET:" + uri.getRawPath());
        String response = md5(a1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + a2);
        String authorization = String.format(
                "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", " +
                        "response=\"%s\", opaque=\"%s\", qop=auth, nc=%s, cnonce=\"%s\"",
                username, realm, nonce, uri.getRawPath(), response, opaque, nc, cnonce);
        HttpRequest request = HttpRequest.newBuilder(uri).header("Authorization", authorization).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private String challengeValue(String challenge, String name) {
        Matcher matcher = Pattern.compile("(?:^|[,\\s])" + name + "=\"([^\"]+)\"").matcher(challenge);
        assertTrue(matcher.find(), () -> "Missing " + name + " in DIGEST challenge");
        return matcher.group(1);
    }

    private String md5(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("MD5").digest(value.getBytes(StandardCharsets.ISO_8859_1));
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) {
            hex.append(String.format("%02x", b & 0xff));
        }
        return hex.toString();
    }
}
