// see https://github.com/panva/openid-client/issues/718

import test from 'ava'
import * as client from '../src/index.js'
import { Strategy } from '../src/passport.js'
import * as undici from 'undici'
import type * as express from 'express'
import * as passport from 'passport'

// At the top with other interfaces
interface MockSession {
    [key: string]: {
        code_verifier?: string;
        state?: string;
    } | undefined;
}

// Mock minimal express Request
const createMockRequest = (session: MockSession = {}): express.Request & { session: MockSession } => {
    return {
        session,
        protocol: 'https',
        host: 'example.com',
        originalUrl: '/callback',
    } as express.Request & { session: MockSession }
}

test('adds state parameter to the repsonse url', async (t) => {
    const agent = new undici.MockAgent()
    agent.disableNetConnect()

    const mockAgent = agent.get('https://auth-server.example.com')

    mockAgent
        .intercept({
            method: 'GET',
            path: '/.well-known/openid-configuration',
        })
        .reply(
            200,
            {
                issuer: 'https://auth-server.example.com',
                authorization_endpoint: 'https://auth-server.example.com/auth',
                token_endpoint: 'https://auth-server.example.com/token',
                code_challenge_methods_supported: ['S256'],
                response_types_supported: ['code', 'id_token'],
            },
            {
                headers: {
                    'content-type': 'application/json',
                },
            },
        )

    const config = await client.discovery(
        new URL('https://auth-server.example.com'),
        'client-id',
        {
            response_types: ['id_token'],
            client_secret: 'client-secret'

        },
        undefined,
        {
            [client.customFetch]: (url: string, options: any) =>
                undici.fetch(url, { ...options, dispatcher: agent }) as unknown as Promise<Response>
        },
    )

    const strategy = new Strategy(
        {
            config,
            callbackURL: 'https://example.com/callback',
            scope: 'openid profile',
        },
        () => { },
    )

    const req = createMockRequest({})
    let redirectUrl: string | undefined

    const strategyContext = {
        ...Strategy.prototype,
        ...strategy,
        redirect(url: string) { redirectUrl = url },
        error(err: Error) { t.fail(err.message) },
        success() { },
        fail() { },
        pass() { },
        authenticate() { },
        currentUrl() { return new URL('https://example.com/callback') },
        authorizationRequestParams: Strategy.prototype.authorizationRequestParams.bind(strategy),
        authorizationCodeGrantParameters: Strategy.prototype.authorizationCodeGrantParameters.bind(strategy),
    } as unknown as passport.StrategyCreated<Strategy, Strategy & passport.StrategyCreatedStatic>

    await strategy.authorizationRequest.call(
        strategyContext,
        req,
        {},
    )

    t.truthy(redirectUrl)
    const parsedUrl = new URL(redirectUrl!)

    // Verify state parameter is present
    t.truthy(parsedUrl.searchParams.get('state'))

    t.truthy(req.session['auth-server.example.com']?.state)

    t.notThrows(() => agent.assertNoPendingInterceptors())
}) 