'use strict';

import {Env} from './worker';
import {parse} from 'cookie';

export interface UserMetadata {
    year: number;
    index: number;
}

type CodeStateVerification = {error: Response} |
                             {code: string, error: false, state: string};

type EmailVerification = {error: Response} |
                         {metadata: UserMetadata, error: null};

/**
 * Verifies the code query parameter exists in the request and that the state
 * parameter is equal to the user's state cookie.
 * @param request Current request data
 * @returns Code and state, or error if the verification failed
 */
export function verifyCodeAndState(request: Request): CodeStateVerification {
    const query = new URL(request.url).searchParams;
    const code = query.get('code');
    const state = query.get('state');
    const stateCookie = parse(request.headers.get('Cookie') || '')['state'];
    if (!code) {
        return {
            error: new Response('Missing OAuth authorization code.', {
                status: 400
            })
        };
    }
    if (state !== stateCookie) {
        return {
            error: new Response('Cross-site request forgery detected.', {
                status: 403
            })
        };
    }
    return {
        code,
        error: false,
        state
    };
}

/**
 * Verifies the user's email adheres to specific conventions.
 * @param env Environment variables with required configuration
 * @param email User's email
 * @returns Error response if an error occurred
 */
export function verifyEmail(env: Env, email: string): EmailVerification {
    const regex = new RegExp(env.AAD_EMAIL_REGEX, 'u');
    const match = regex.exec(email);
    if (!match) {
        return {
            error: new Response('Your email is not valid for this AAD.', {
                status: 403
            })
        };
    }
    const forbiddenAddresses = env.AAD_DENYLIST.split(',');
    if (forbiddenAddresses.includes(email)) {
        return {
            error: new Response('Nice try ;)', {
                status: 403
            })
        };
    }
    if (match[1] && match[2]) {
        const lastTwoYearDigits = Number(match[1]);
        return {
            error: null,
            metadata: {
                index: Number(match[2]),
                year: lastTwoYearDigits > 80 ?
                    1900 + lastTwoYearDigits :
                    2000 + lastTwoYearDigits
            }
        };
    }
    return {
        error: null,
        metadata: {
            index: 0,
            year: 0
        }
    };
}
