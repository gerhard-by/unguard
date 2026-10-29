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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.Collections;
import java.util.List;

/**
 * Tomcat realm holding a single admin user in memory.
 *
 * <p>DIGEST authentication against this realm goes through RealmBase#getDigest,
 * the vulnerable function of CVE-2026-43512. On an unpatched Tomcat, getDigest
 * does not null-check the result of {@link #getPassword(String)}: for an unknown
 * user getPassword returns {@code null}, which Java concatenates as the literal
 * string {@code "null"}, so the server computes {@code A1 = MD5(user:realm:null)}.
 * An attacker who authenticates as any non-existent user with the literal
 * password {@code "null"} therefore produces a matching digest. The patched
 * Tomcat (fixed deploy variant bumps {@code tomcat.version} to 9.0.118) adds the
 * null guard, so getDigest returns {@code null} and authentication fails.
 *
 * <p>This realm is deliberately a <em>vulnerable configuration</em>: {@link
 * #getPrincipal(String)} trusts a matched digest instead of independently
 * re-validating that the user exists. A hardened realm (e.g. Tomcat's stock
 * UserDatabaseRealm) re-checks existence in getPrincipal and so blocks the
 * bypass even on an unpatched Tomcat; that is why the public PoC could only
 * reach a matching-digest-then-401 dead end. Here the sole gate is the Tomcat
 * getDigest fix, so the fixed/vulnerable image flip alone decides exploitability.
 */
public class InMemoryDigestRealm extends RealmBase {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryDigestRealm.class);

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
        // VULNERABLE realm configuration: trust whatever digest already matched in
        // RealmBase#getDigest instead of re-validating that the user exists. On an
        // unpatched Tomcat this lets the CVE-2026-43512 null-password bypass land --
        // an unknown user authenticates as admin with the literal password "null".
        // The stock UserDatabaseRealm returns null here for an unknown user, which
        // is why the bypass is not reproducible against it. Grant the admin role to
        // whoever authenticated; the known admin keeps its real credentials.
        String credentials = this.username.equals(username) ? password : null;
        List<String> roles = Collections.singletonList(role);
        // Routine audit of every admin principal we hand out. The username is the
        // one attacker-controlled value visible here; legitimate access always
        // resolves to the configured admin account.
        logger.info("Admin access granted: user={} roles={}", username, roles);
        return new GenericPrincipal(username, credentials, roles);
    }
}
