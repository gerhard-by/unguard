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

import org.apache.tomcat.util.security.ConcurrentMessageDigest;
import org.dynatrace.profileservice.security.InMemoryDigestRealm;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DigestRealmTests {

    @Test
    void unknownUserHasNoDigest() throws Exception {
        ConcurrentMessageDigest.init("MD5");
        TestRealm realm = new TestRealm();

        assertNull(realm.digest("unknown"));
    }

    @Test
    void knownUserHasExpectedDigest() throws Exception {
        ConcurrentMessageDigest.init("MD5");
        TestRealm realm = new TestRealm();

        assertEquals("05ad8c8b9ef9515bc57de20b573c23d0", realm.digest("admin"));
    }

    private static class TestRealm extends InMemoryDigestRealm {
        TestRealm() {
            super("admin", "unguard-admin", "admin");
        }

        String digest(String username) {
            return getDigest(username, "unguard-admin", "MD5");
        }
    }
}
