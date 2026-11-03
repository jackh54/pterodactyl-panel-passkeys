<?php

namespace PanelPasskeys\Auth;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use lbuchs\WebAuthn\WebAuthnException;
use PanelPasskeys\Tables;
use Pterodactyl\Contracts\Users\CompletesLogins;
use Pterodactyl\Exceptions\DisplayException;
use Pterodactyl\Facades\Activity;
use Pterodactyl\Http\Controllers\Auth\AbstractLoginController;
use Pterodactyl\Models\User;
use Throwable;

/**
 * Sign in with a passkey (discoverable credential, user verification required).
 *
 * A successful passkey sign-in is a complete login: the authenticator proved possession of the
 * key and verified the user (biometric or PIN), so no TOTP step follows (an account with TOTP skips
 * the checkpoint). Password sign-in is unchanged. The login goes through the panel's CompletesLogins
 * action, so anything another extension wraps around sign-in (e.g. refusing suspended accounts)
 * applies to passkeys too.
 *
 * Every failure returns the same message, counts towards the panel's normal login lockout and
 * fires the same failed-login event as a wrong password, so the endpoint reveals nothing about
 * which accounts or passkeys exist.
 */
final class PasskeyLoginController extends AbstractLoginController
{
    public const string FAILED = 'That passkey could not be used to sign in.';

    public function __construct(private readonly PasskeyService $passkeys) {}

    public function options(Request $request): JsonResponse
    {
        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            $this->sendLockoutResponse($request);
        }

        $webAuthn = $this->passkeys->webAuthn();
        // No allowCredentials: the browser offers the passkeys it holds for this site.
        $args = $webAuthn->getGetArgs([], 60, true, true, true, true, true, true);
        $this->passkeys->rememberChallenge($request, 'get', $webAuthn->getChallenge());

        return new JsonResponse($args);
    }

    public function login(Request $request, CompletesLogins $logins): JsonResponse
    {
        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);
            $this->sendLockoutResponse($request);
        }

        // Single use: removed from the session before anything else is looked at.
        $challenge = $this->passkeys->consumeChallenge($request, 'get');
        if ($challenge === null) {
            $this->fail($request, null, 'missing or expired challenge');
        }

        $credentialRaw = PasskeyService::b64urlDecodeOrNull($this->field($request, 'id', 1024));
        $clientDataJSON = PasskeyService::b64urlDecodeOrNull($this->field($request, 'client_data_json', 4096));
        $authenticatorData = PasskeyService::b64urlDecodeOrNull($this->field($request, 'authenticator_data', 4096));
        $signature = PasskeyService::b64urlDecodeOrNull($this->field($request, 'signature', 2048));
        $userHandle = PasskeyService::b64urlDecodeOrNull($this->field($request, 'user_handle', 512));

        if ($credentialRaw === null || $clientDataJSON === null || $authenticatorData === null || $signature === null) {
            $this->fail($request, null, 'malformed request');
        }

        if (! $this->passkeys->originMatches($clientDataJSON)) {
            $this->fail($request, null, 'unexpected origin');
        }

        $passkey = DB::table(Tables::passkeys())->where('credential_id', PasskeyService::b64url($credentialRaw))->first();
        if ($passkey === null) {
            $this->fail($request, null, 'unknown credential');
        }

        $user = User::query()->find($passkey->user_id);
        if (! $user instanceof User) {
            $this->fail($request, null, 'credential without user');
        }

        // The browser did not know who was signing in, so the authenticator must say, and the
        // handle it returns must belong to the owner of this credential.
        $expectedHandle = $this->passkeys->storedUserHandle($user);
        if ($userHandle === null || $expectedHandle === null || ! hash_equals($expectedHandle, $userHandle)) {
            $this->fail($request, $user, 'user handle missing or mismatched');
        }

        $webAuthn = $this->passkeys->webAuthn();
        try {
            $webAuthn->processGet(
                $clientDataJSON,
                $authenticatorData,
                $signature,
                (string) $passkey->public_key,
                $challenge,
                (int) $passkey->sign_count,
                true,   // user verification required
                true    // user presence required
            );
        } catch (WebAuthnException $e) {
            $this->fail($request, $user, $e->getMessage());
        } catch (Throwable $e) {
            // Malformed authenticator data can surface as other exceptions inside the library.
            $this->fail($request, $user, 'verification error: '.$e::class);
        }

        // Compare-and-swap so the stored counter only ever goes up. A counting authenticator whose
        // counter another sign-in already reached or passed is a clone signal, so that fails too.
        $counter = max(0, (int) $webAuthn->getSignatureCounter());
        $raised = DB::table(Tables::passkeys())->where('id', $passkey->id)->where('sign_count', '<', $counter)->update(['sign_count' => $counter]);
        if ($counter > 0 && $raised === 0) {
            $this->fail($request, $user, 'signature counter raced or regressed');
        }

        DB::table(Tables::passkeys())->where('id', $passkey->id)->update([
            'last_used_at' => now(),
            'last_used_ip' => $request->ip(),
            'updated_at' => now(),
        ]);

        Activity::event('auth:passkey')->withRequestMetadata()->subject($user)->property('name', (string) $passkey->name)->log();

        // establish() regenerates the session id but keeps the old session's stored copy, which
        // still holds this challenge; a copied pre-login cookie could replay the assertion with it.
        // Destroy the pre-login session first (its data carries over to the new id).
        $request->session()->migrate(true);

        return $this->sendLoginResponse($logins->establish($user), $request);
    }

    /**
     * Shares the lockout bucket of the panel's own login steps: core's key is the lower-cased
     * "email" input plus the IP, and its login form never sends an email, so it is "|<ip>".
     * Passkey requests ignore any input here so a client cannot pick a fresh bucket.
     */
    protected function throttleKey(Request $request): string
    {
        return Str::transliterate('|'.($request->ip() ?? 'unknown'));
    }

    private function field(Request $request, string $key, int $max): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' && strlen($value) <= $max ? $value : null;
    }

    /**
     * @throws DisplayException
     */
    private function fail(Request $request, ?User $user, string $reason): never
    {
        Log::info('Panel Passkeys: sign-in rejected', ['reason' => $reason, 'user' => $user?->id, 'ip' => $request->ip()]);
        $this->incrementLoginAttempts($request);
        $this->fireFailedLoginEvent($user, ['method' => 'passkey']);

        throw new DisplayException(self::FAILED);
    }
}
