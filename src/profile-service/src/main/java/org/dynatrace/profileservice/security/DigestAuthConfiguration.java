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

import org.apache.catalina.authenticator.DigestAuthenticator;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

/**
 * Protects /admin/* with Tomcat container-managed DIGEST authentication.
 */
@Component
public class DigestAuthConfiguration implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    public static final String REALM_NAME = "unguard-admin";
    private static final String ADMIN_ROLE = "admin";

    private final String adminUsername;
    private final String adminPassword;

    public DigestAuthConfiguration(@Value("${ADMIN_USERNAME:admin}") String adminUsername,
                                   @Value("${ADMIN_PASSWORD:unguard-admin}") String adminPassword) {
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
    }

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        factory.addContextCustomizers(context -> {
            SecurityCollection collection = new SecurityCollection();
            collection.addPattern("/admin/*");

            SecurityConstraint constraint = new SecurityConstraint();
            constraint.addAuthRole(ADMIN_ROLE);
            constraint.addCollection(collection);
            context.addConstraint(constraint);
            context.addSecurityRole(ADMIN_ROLE);

            LoginConfig loginConfig = new LoginConfig();
            loginConfig.setAuthMethod("DIGEST");
            loginConfig.setRealmName(REALM_NAME);
            context.setLoginConfig(loginConfig);

            context.setRealm(new InMemoryDigestRealm(adminUsername, adminPassword, ADMIN_ROLE));
            // Spring Boot's embedded Tomcat does not install authenticators from the login config
            context.getPipeline().addValve(new DigestAuthenticator());
        });
    }
}
