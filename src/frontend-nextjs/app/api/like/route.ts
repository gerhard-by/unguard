import { NextResponse } from 'next/server';

import { unlikePost } from '@/services/api/LikeService';
import { withForwardedClientIp } from '@/lib/clientIpForwarding';

/** @swagger
 * /ui/api/like/unlike:
 *   delete:
 *     description: Unlike a post by its ID.
 */

export async function DELETE(req: Request): Promise<NextResponse> {
    return withForwardedClientIp(req, async () => {
        const { searchParams } = new URL(req.url);
        const postId = searchParams.getAll('postId');
        const res = await unlikePost(postId);

        return NextResponse.json(res.data, { status: res.status });
    });
}
