import express from 'express';
import { get, merge } from 'lodash';

import { getUserBySessionToken } from 'db/users';


/**
 * This middleware function checks if the current user is the owner of the resource being requested.
 * If the user is not the owner, they will receive a 403 Forbidden response.
 */

export const isOwner = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const { id } = req.params;
        const currentUserid = get(req, 'identity._id') as string;

        if (!currentUserid) {
            return res.sendStatus(403);
        }

        if (currentUserid.toString() !== id.toString()) {
            return res.sendStatus(403);
        }

        next();
    } catch (error) {
        console.log(error);
        return res.sendStatus(400); 
    }
}

/**
 * This middleware function checks if the current user is authenticated.
 * If the user is not authenticated, they will receive a 403 Forbidden response.
 */

export const isAuthenticated = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const sessionToken = req.cookies['CARTOON-AUTH'];

        if (!sessionToken) {
            return res.sendStatus(403);
        }

        const existingUser = await getUserBySessionToken(sessionToken);

        if (!existingUser) {
            return res.sendStatus(403);
        }

        merge(req, { user: existingUser });

        return next();
    } catch (error) {
        console.log(error);
        return res.sendStatus(400);
    }
}
