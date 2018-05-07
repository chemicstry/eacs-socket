import * as WebSocket from 'ws';
import * as jwt from 'jsonwebtoken';
import * as http from 'http';
import { EventEmitter } from 'events';

class EACSToken
{
    payload: any;
    identifier: string;

    constructor(payload: any)
    {
        if (typeof payload.identifier != 'string')
            throw new Error('Token payload does not have identifier field');
        
        if (!Array.isArray(payload.permissions))
            throw new Error('Token payload does not have correct permissions field');
        
        this.payload = payload;
        this.identifier = payload.identifier;
    }

    hasPermission(perm: string): boolean
    {
        return this.payload.permissions.includes(perm);
    }
}

interface EACSSocketOptions extends WebSocket.ServerOptions
{
    jwtPubKey?: string,
}

type wsClientInfo = { origin: string; secure: boolean; req: http.IncomingMessage };
type wsVerifyCallback = (res: boolean, code?: number, message?: string) => void;

class EACSSocket extends WebSocket.Server
{
    options: EACSSocketOptions;

    constructor(options: EACSSocketOptions)
    {
        super({
            ...<WebSocket.ServerOptions>options,
            verifyClient: (info, cb) => this.verifyClient(info, cb)
        });

        this.options = options;

        if (!this.options.jwtPubKey)
            console.log('Warning: not using JWT authentication. Public key is missing.');
    }

    // Authenticates new websocket connection using JWT
    private verifyClient(info: wsClientInfo, cb: wsVerifyCallback)
    {
        // Not using authentication
        if (!this.options.jwtPubKey)
        {
            cb(true);
            return;
        }

        // Get token from headers
        let token = info.req.headers.token;

        if (token) {
            jwt.verify(<string>token, this.options.jwtPubKey, (err, decoded) => {
                if (err) {
                    console.log(`JWT verification failed for ${info.req.connection.remoteAddress}`);
                    cb(false, 401, 'Unauthorized');
                } else {
                    try {
                        // Hack typescript to insert additional data
                        (<any>info.req).token = new EACSToken(decoded);
                        cb(true);
                    } catch (e) {
                        console.log(`JWT token parsing failed for ${info.req.connection.remoteAddress}: ${e}`);
                        cb(false, 401, 'Unauthorized');
                    }
                }
            });
        } else {
            console.log(`Token not found for ${info.req.connection.remoteAddress}`);
            cb(false, 401, 'Unauthorized');
        }
    }
}

export {
    EACSSocket,
    EACSSocketOptions,
    EACSToken
}
