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

package org.dynatrace.profileservice.security;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;

import java.security.Principal;
import java.util.Collections;

/**
 * Tomcat realm holding a single admin user in memory.
 * DIGEST authentication against this realm goes through RealmBase#getDigest,
 * the vulnerable function of CVE-2026-43512.
 */
public class InMemoryDigestRealm extends RealmBase {

    private final String username;
    private final String password;
    private final String role;

    public InMemoryDigestRealm(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    @Override
    protected String getPassword(String username) {
        return this.username.equals(username) ? password : null;
    }

    @Override
    protected Principal getPrincipal(String username) {
        if (!this.username.equals(username)) {
            return null;
        }
        return new GenericPrincipal(username, password, Collections.singletonList(role));
    }
}
