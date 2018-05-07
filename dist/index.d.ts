/// <reference types="ws" />
import * as WebSocket from 'ws';
declare class EACSToken {
    payload: any;
    identifier: string;
    constructor(payload: any);
    hasPermission(perm: string): boolean;
}
interface EACSSocketOptions extends WebSocket.ServerOptions {
    jwtPubKey?: string;
}
declare class EACSSocket extends WebSocket.Server {
    options: EACSSocketOptions;
    constructor(options: EACSSocketOptions);
    private verifyClient(info, cb);
}
export { EACSSocket, EACSSocketOptions, EACSToken };
