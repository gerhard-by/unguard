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

import org.dynatrace.profileservice.dal.DatabaseManager;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.server.LocalServerPort;

import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"ADMIN_USERNAME=test-admin", "ADMIN_PASSWORD=test-password"})
class DigestAuthenticationTests {

    @LocalServerPort
    private int port;

    @MockBean
    private DatabaseManager databaseManager;

    @Test
    void rejectsUnknownUserWithLiteralNullPassword() throws Exception {
        assertEquals(401, adminResponse("unknown-user", "null"));
    }

    @Test
    void acceptsKnownUser() throws Exception {
        assertEquals(200, adminResponse("test-admin", "test-password"));
    }

    private int adminResponse(String username, String password) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL("http://localhost:" + port + "/admin/stats").openConnection();
        connection.setAuthenticator(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password.toCharArray());
            }
        });
        try {
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }
}
