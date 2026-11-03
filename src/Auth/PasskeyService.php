<?php

namespace PanelPasskeys\Auth;

use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\WebAuthn;
use PanelPasskeys\Tables;
use Pterodactyl\Models\User;

/**
 * WebAuthn passkeys: the relying party, challenges and the encoding helpers.
 *
 * Security model:
 * - The relying party is the panel host from APP_URL, and the browser origin must match APP_URL
 *   exactly (scheme, host and port, compared with hash_equals). The library's own origin check
 *   only does a suffix match, so this stricter check always runs first.
 * - User verification (biometric/PIN) and user presence are always required, so a passkey
 *   sign-in counts as multi-factor on its own.
 * - Challenges are 32 random bytes, bound to the session, the ceremony type and (for
 *   registration) the user. They expire after 5 minutes and are removed from the session before
 *   anything is verified, so each one is single use even when verification fails.
 * - The WebAuthn user.id is a random 32-byte handle, never the database id, email or username.
 * - Attestation "none" is requested, so no device information is collected; the common
 *   formats stay allowed in case a platform ignores the preference.
 */
final class PasskeyService
{
    public const int CHALLENGE_TTL = 300;

    public const int NAME_MAX = 64;

    /** credential_id column width (base64url). */
    public const int CREDENTIAL_ID_MAX = 512;

    public const array FORMATS = ['none', 'packed', 'apple', 'android-key', 'fido-u2f', 'tpm'];

    private const string SESSION_KEY = 'panel-passkeys.webauthn';

    public function rpId(): string
    {
        return strtolower((string) parse_url((string) config('app.url'), PHP_URL_HOST));
    }

    /**
     * scheme://host[:port] of APP_URL, lower case, no trailing slash. A default port (443 for https,
     * 80 for http) is left out, as browsers leave it out of the origin they report.
     */
    public function expectedOrigin(): string
    {
        $url = parse_url((string) config('app.url'));
        $scheme = strtolower($url['scheme'] ?? 'https');
        $origin = $scheme.'://'.strtolower($url['host'] ?? '');
        $port = $url['port'] ?? null;

        return $port === null || ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80) ? $origin : "{$origin}:{$port}";
    }

    public function webAuthn(): WebAuthn
    {
        return new WebAuthn((string) config('app.name', 'Pterodactyl'), $this->rpId(), self::FORMATS, true);
    }

    /**
     * The user's opaque WebAuthn handle as raw bytes, created on first use.
     */
    public function userHandle(User $user): string
    {
        $row = DB::table(Tables::prefs())->where('user_id', $user->id)->first();
        if ($row !== null) {
            return self::b64urlDecode((string) $row->webauthn_user_handle);
        }

        $handle = random_bytes(32);
        try {
            DB::table(Tables::prefs())->insert([
                'user_id' => $user->id,
                'webauthn_user_handle' => self::b64url($handle),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (QueryException $e) {
            // Created by a concurrent request: use the stored handle.
            $row = DB::table(Tables::prefs())->where('user_id', $user->id)->first();
            if ($row === null) {
                throw $e;
            }

            return self::b64urlDecode((string) $row->webauthn_user_handle);
        }

        return $handle;
    }

    /** The user's stored WebAuthn handle as raw bytes, or null when none exists yet (no side effects). */
    public function storedUserHandle(User $user): ?string
    {
        $row = DB::table(Tables::prefs())->where('user_id', $user->id)->first();

        return $row === null ? null : self::b64urlDecodeOrNull((string) $row->webauthn_user_handle);
    }

    /**
     * Stores the challenge for one ceremony in the session, replacing any previous one of the same type.
     */
    public function rememberChallenge(Request $request, string $type, ByteBuffer $challenge, ?int $userId = null): void
    {
        $request->session()->put(self::SESSION_KEY.".{$type}", [
            'challenge' => self::b64url($challenge->getBinaryString()),
            'expires' => time() + self::CHALLENGE_TTL,
            'user' => $userId,
        ]);
    }

    /**
     * Removes the stored challenge (single use) and returns it, or null when it is missing,
     * expired or was issued to another user.
     */
    public function consumeChallenge(Request $request, string $type, ?int $userId = null): ?string
    {
        $data = $request->session()->pull(self::SESSION_KEY.".{$type}");

        if (! is_array($data) || ! is_int($data['expires'] ?? null) || $data['expires'] < time()
            || ($data['user'] ?? null) !== $userId || ! is_string($data['challenge'] ?? null)) {
            return null;
        }

        $challenge = self::b64urlDecodeOrNull($data['challenge']);
        if ($challenge === null || strlen($challenge) !== 32) {
            return null;
        }

        // Session writes are not locked, so two concurrent requests could both read the same
        // challenge. An atomic cache marker makes the challenge single use across them too.
        if (! Cache::add('panel-passkeys-used:'.hash('sha256', $type.':'.$challenge), true, self::CHALLENGE_TTL)) {
            return null;
        }

        return $challenge;
    }

    /**
     * Strict origin check against APP_URL, run before the library's own checks.
     */
    public function originMatches(string $clientDataJSON): bool
    {
        $data = json_decode($clientDataJSON);
        if (! is_object($data) || ! is_string($data->origin ?? null)) {
            return false;
        }

        return hash_equals($this->expectedOrigin(), strtolower($data->origin));
    }

    public static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** Strict base64url decode (no padding, no other characters); null when malformed. */
    public static function b64urlDecodeOrNull(mixed $value): ?string
    {
        if (! is_string($value) || $value === '' || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1 || strlen($value) % 4 === 1) {
            return null;
        }

        $decoded = base64_decode(strtr($value, '-_', '+/').str_repeat('=', (4 - strlen($value) % 4) % 4), true);

        return $decoded === false ? null : $decoded;
    }

    public static function b64urlDecode(string $value): string
    {
        $decoded = self::b64urlDecodeOrNull($value);
        if ($decoded === null) {
            throw new \UnexpectedValueException('Malformed base64url value.');
        }

        return $decoded;
    }

    /** 16 raw bytes (or a ByteBuffer of them) as a canonical UUID string, else null. */
    public static function formatAaguid(mixed $aaguid): ?string
    {
        $bytes = $aaguid instanceof ByteBuffer ? $aaguid->getBinaryString() : (is_string($aaguid) ? $aaguid : null);
        if ($bytes === null || strlen($bytes) !== 16) {
            return null;
        }

        $hex = bin2hex($bytes);

        return sprintf('%s-%s-%s-%s-%s', substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20));
    }

    /** A display name for a passkey: no tags or control characters, 1-64 characters. */
    public static function cleanName(string $name): string
    {
        $name = strip_tags($name);
        $name = (string) preg_replace('/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $name);
        $name = trim((string) preg_replace('/\s+/u', ' ', $name));

        return $name === '' ? 'Passkey' : mb_substr($name, 0, self::NAME_MAX);
    }
}
