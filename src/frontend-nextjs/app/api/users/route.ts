import { NextResponse } from 'next/server';

import { fetchAllUsers } from '@/services/api/UserService';
import { withForwardedClientIp } from '@/lib/clientIpForwarding';

/**
 * @swagger
 * /ui/api/users:
 *   get:
 *     description: Get all users with optional filters.
 */

export async function GET(request: Request): Promise<NextResponse> {
    return withForwardedClientIp(request, async () => {
        const { searchParams } = new URL(request.url);

        const params = {
            name: searchParams.get('name'),
            roles: searchParams.getAll('roles'),
        };

        const users = await fetchAllUsers(params);

        return NextResponse.json(users);
    });
}
