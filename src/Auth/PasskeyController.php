<?php

namespace PanelPasskeys\Auth;

use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use lbuchs\WebAuthn\WebAuthnException;
use PanelPasskeys\Settings;
use PanelPasskeys\Tables;
use Pterodactyl\Facades\Activity;
use Pterodactyl\Models\User;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;

/**
 * The signed-in user's passkeys (session only, see routes/client/passkeys.php).
 *
 * Adding or removing a passkey needs the account password (5 tries a minute per user), is
 * written to the activity log and emails the account owner.
 */
final class PasskeyController
{
    public function __construct(private readonly PasskeyService $passkeys, private readonly PasskeyMailer $mailer) {}

    public function index(Request $request): JsonResponse
    {
        $user = $this->user($request);
        $prefs = DB::table(Tables::prefs())->where('user_id', $user->id)->first();

        $passkeys = DB::table(Tables::passkeys())
            ->where('user_id', $user->id)
            ->orderBy('created_at')
            ->orderBy('id')
            ->get(['id', 'name', 'backup_eligible', 'last_used_at', 'created_at'])
            ->map(fn (object $p): array => [
                'id' => (int) $p->id,
                'name' => (string) $p->name,
                'synced' => (bool) $p->backup_eligible,
                // ISO 8601 with offset, so browsers in any timezone show the right time.
                'last_used_at' => $p->last_used_at ? CarbonImmutable::parse($p->last_used_at)->toAtomString() : null,
                'created_at' => CarbonImmutable::parse($p->created_at)->toAtomString(),
            ])
            ->values();

        return new JsonResponse([
            'passkeys' => $passkeys,
            // The admin can turn the dashboard notice off for everyone.
            'prompt_dismissed' => ! Settings::dashboardPrompt() || ($prefs !== null && $prefs->passkey_prompt_dismissed_at !== null),
            'max' => Settings::maxPerUser(),
        ]);
    }

    /**
     * Step 1 of adding a passkey: confirm the password, then return the creation options.
     */
    public function options(Request $request): JsonResponse
    {
        $user = $this->user($request);
        $this->confirmPassword($request, $user);

        $this->assertBelowLimit($user);

        $exclude = DB::table(Tables::passkeys())->where('user_id', $user->id)->pluck('credential_id')
            ->map(fn (string $id): ?string => PasskeyService::b64urlDecodeOrNull($id))
            ->filter()
            ->values()
            ->all();

        $webAuthn = $this->passkeys->webAuthn();
        $name = trim("{$user->name_first} {$user->name_last}");
        $args = $webAuthn->getCreateArgs(
            $this->passkeys->userHandle($user),
            $user->email,
            $name !== '' ? $name : $user->username,
            60,
            true,       // resident key required: passkeys work without typing a username
            true,       // user verification required
            null,       // any authenticator (phone, security key, built-in)
            $exclude
        );
        // The library asks for "indirect" whenever more than one format is allowed; nothing here
        // validates attestation certificates, so ask for none and collect no device information.
        $args->publicKey->attestation = 'none';
        $this->passkeys->rememberChallenge($request, 'create', $webAuthn->getChallenge(), $user->id);

        return new JsonResponse($args);
    }

    /**
     * Step 2 of adding a passkey: verify the authenticator's response and store the credential.
     */
    public function store(Request $request): JsonResponse
    {
        $user = $this->user($request);
        // Pull the challenge first so it is gone even if anything below fails.
        $challenge = $this->passkeys->consumeChallenge($request, 'create', $user->id);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:'.PasskeyService::NAME_MAX],
            'client_data_json' => ['required', 'string', 'max:4096'],
            'attestation_object' => ['required', 'string', 'max:16384'],
        ]);

        if ($challenge === null) {
            throw new BadRequestHttpException('This passkey request has expired. Please try again.');
        }

        $clientDataJSON = PasskeyService::b64urlDecodeOrNull($data['client_data_json']);
        $attestationObject = PasskeyService::b64urlDecodeOrNull($data['attestation_object']);
        if ($clientDataJSON === null || $attestationObject === null || ! $this->passkeys->originMatches($clientDataJSON)) {
            Log::info('Panel Passkeys: registration rejected', ['user' => $user->id, 'reason' => 'malformed data or unexpected origin']);
            throw new BadRequestHttpException('That passkey could not be verified. Please try again.');
        }

        try {
            $result = $this->passkeys->webAuthn()->processCreate(
                $clientDataJSON,
                $attestationObject,
                $challenge,
                true,   // user verification required
                true,   // user presence required
                false   // no attestation roots configured; attestation is "none"
            );
        } catch (WebAuthnException $e) {
            Log::info('Panel Passkeys: registration rejected', ['user' => $user->id, 'reason' => $e->getMessage()]);
            throw new BadRequestHttpException('That passkey could not be verified. Please try again.');
        } catch (\Throwable $e) {
            // Malformed data can surface as other errors inside the library (e.g. a TypeError).
            Log::info('Panel Passkeys: registration rejected', ['user' => $user->id, 'reason' => 'verification error: '.$e::class]);
            throw new BadRequestHttpException('That passkey could not be verified. Please try again.');
        }

        $rawId = $result->credentialId instanceof \lbuchs\WebAuthn\Binary\ByteBuffer ? $result->credentialId->getBinaryString() : (string) $result->credentialId;
        $credentialId = PasskeyService::b64url($rawId);
        if ($rawId === '' || strlen($credentialId) > PasskeyService::CREDENTIAL_ID_MAX || ! is_string($result->credentialPublicKey ?? null)) {
            throw new BadRequestHttpException('This kind of passkey is not supported. Please try another device.');
        }

        $name = PasskeyService::cleanName($data['name']);

        try {
            $id = DB::transaction(function () use ($user, $credentialId, $result, $name): int {
                // Serialises concurrent adds for one account, so the limit holds.
                DB::table('users')->where('id', $user->id)->lockForUpdate()->first(['id']);

                if (DB::table(Tables::passkeys())->where('credential_id', $credentialId)->exists()) {
                    throw new BadRequestHttpException('That passkey is already registered.');
                }
                $this->assertBelowLimit($user);

                return (int) DB::table(Tables::passkeys())->insertGetId([
                    'user_id' => $user->id,
                    'name' => $name,
                    'credential_id' => $credentialId,
                    'public_key' => $result->credentialPublicKey,
                    'sign_count' => max(0, (int) $result->signatureCounter),
                    'aaguid' => PasskeyService::formatAaguid($result->AAGUID ?? null),
                    'backup_eligible' => (bool) ($result->isBackupEligible ?? false),
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            });
        } catch (QueryException $e) {
            // Unique index on credential_id: registered by a concurrent request.
            Log::info('Panel Passkeys: registration rejected', ['user' => $user->id, 'reason' => 'insert failed: '.$e->getCode()]);
            throw new BadRequestHttpException('That passkey is already registered.');
        }

        Activity::event('user:passkey.create')->subject($user)->property('name', $name)->log();
        $this->mailer->send($user, "A passkey named \"{$name}\" was added to your account.");

        return new JsonResponse(['id' => $id, 'name' => $name], Response::HTTP_CREATED);
    }

    public function destroy(Request $request, string $passkey): JsonResponse
    {
        $user = $this->user($request);
        $this->confirmPassword($request, $user);

        $row = DB::table(Tables::passkeys())->where('id', (int) $passkey)->where('user_id', $user->id)->first();
        if ($row === null) {
            throw new NotFoundHttpException('That passkey was not found.');
        }

        DB::table(Tables::passkeys())->where('id', $row->id)->where('user_id', $user->id)->delete();
        Activity::event('user:passkey.delete')->subject($user)->property('name', (string) $row->name)->log();
        $this->mailer->send($user, "The passkey named \"{$row->name}\" was removed from your account.");

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    /**
     * Hides the one-time "you can add a passkey" notice for this account on every device.
     */
    public function dismissPrompt(Request $request): JsonResponse
    {
        $user = $this->user($request);
        $this->passkeys->userHandle($user);
        DB::table(Tables::prefs())->where('user_id', $user->id)->whereNull('passkey_prompt_dismissed_at')->update([
            'passkey_prompt_dismissed_at' => now(),
            'updated_at' => now(),
        ]);

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    private function confirmPassword(Request $request, User $user): void
    {
        $key = 'panel-passkeys-password:'.$user->id;
        if (RateLimiter::tooManyAttempts($key, 5)) {
            throw new TooManyRequestsHttpException(RateLimiter::availableIn($key), 'Too many attempts. Please wait a minute and try again.');
        }

        $password = $request->input('password');
        if (! is_string($password) || $password === '' || strlen($password) > 4096 || ! Hash::check($password, $user->password)) {
            RateLimiter::hit($key, 60);
            throw new BadRequestHttpException('The password provided was not valid.');
        }

        RateLimiter::clear($key);
    }

    private function assertBelowLimit(User $user): void
    {
        $max = Settings::maxPerUser();
        if (DB::table(Tables::passkeys())->where('user_id', $user->id)->count() >= $max) {
            throw new BadRequestHttpException("You already have the maximum of {$max} passkeys.");
        }
    }

    private function user(Request $request): User
    {
        $user = $request->user();
        if (! $user instanceof User) {
            throw new NotFoundHttpException;
        }

        return $user;
    }
}
