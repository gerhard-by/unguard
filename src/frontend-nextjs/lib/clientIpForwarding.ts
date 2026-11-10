import { AsyncLocalStorage } from 'node:async_hooks';

import type { AxiosInstance, InternalAxiosRequestConfig } from 'axios';

/**
 * Propagates the caller's client IP from an incoming frontend request down to the
 * backend microservices as an `X-Forwarded-For` header.
 *
 * Without this, the frontend terminates the inbound connection and every
 * server-side call it makes (via the shared axios instances in `@/axios`)
 * originates from the frontend pod. Backend OneAgents therefore attribute all
 * traffic -- including attacks such as SQL/JNDI/command injection -- to the
 * frontend pod IP instead of the real caller, collapsing distinct attackers into
 * one internal address. Forwarding `X-Forwarded-For` lets each backend's OneAgent
 * resolve the actual client IP, so security findings carry the true source.
 *
 * Implementation: the inbound client IP is stored per request in an
 * AsyncLocalStorage. A single axios request interceptor (installed on every
 * instance) reads it and stamps `X-Forwarded-For` on outgoing calls, so no
 * individual service function needs to know about it.
 */

interface ClientIpContext {
    clientIp?: string;
}

const clientIpStore = new AsyncLocalStorage<ClientIpContext>();

/**
 * Extract the originating client IP from an inbound request's headers. Prefers
 * the first hop of `X-Forwarded-For`, falling back to `X-Client-Ip`.
 */
export function getClientIp(headers: Headers): string | undefined {
    const forwardedFor = headers.get('x-forwarded-for');
    if (forwardedFor) {
        const firstHop = forwardedFor.split(',')[0]?.trim();
        if (firstHop) {
            return firstHop;
        }
    }

    const clientIp = headers.get('x-client-ip');
    if (clientIp) {
        return clientIp.trim();
    }

    return undefined;
}

/**
 * Run a route handler within a context that carries the inbound client IP, so
 * that any backend call made while it runs forwards that IP downstream.
 */
export function withForwardedClientIp<T>(req: Request, handler: () => Promise<T>): Promise<T> {
    return clientIpStore.run({ clientIp: getClientIp(req.headers) }, handler);
}

/**
 * Install the X-Forwarded-For forwarding interceptor on an axios instance.
 * A no-op for requests made outside of a {@link withForwardedClientIp} context.
 */
export function applyClientIpForwarding(instance: AxiosInstance): void {
    instance.interceptors.request.use((config: InternalAxiosRequestConfig) => {
        const clientIp = clientIpStore.getStore()?.clientIp;
        if (clientIp) {
            config.headers.set('X-Forwarded-For', clientIp);
        }
        return config;
    });
}
