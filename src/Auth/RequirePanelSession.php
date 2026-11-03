<?php

namespace PanelPasskeys\Auth;

use Closure;
use Illuminate\Http\Request;
use Laravel\Sanctum\TransientToken;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/**
 * Lets only a signed-in panel session through (Sanctum's stateful TransientToken), never an API
 * key: passkeys are managed from the account page, and the WebAuthn ceremony needs the session.
 */
final class RequirePanelSession
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->user()?->currentAccessToken() instanceof TransientToken || ! $request->hasSession()) {
            throw new AccessDeniedHttpException('Passkeys can only be managed from a signed-in panel session, not with an API key.');
        }

        return $next($request);
    }
}
