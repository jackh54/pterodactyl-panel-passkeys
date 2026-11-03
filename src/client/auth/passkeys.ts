import { http } from '@pterodactyl/sdk';

// Passkeys (WebAuthn) with the browser's built-in API. Endpoints: extension/routes/{web,client}/passkeys.php.

const ACCOUNT = '/api/client/extensions/panel-passkeys/passkeys';
const SIGN_IN = '/extensions/panel-passkeys/passkey';

export const PASSKEYS_QUERY_KEY = ['panel-passkeys', 'passkeys'] as const;

export interface Passkey {
    id: number;
    name: string;
    synced: boolean;
    last_used_at: string | null;
    created_at: string;
}

export interface PasskeyList {
    passkeys: Passkey[];
    promptDismissed: boolean;
    max: number;
}

export const passkeysSupported = (): boolean =>
    typeof window !== 'undefined' &&
    window.isSecureContext &&
    typeof window.PublicKeyCredential === 'function' &&
    !!navigator.credentials;

export const fromB64url = (value: string): ArrayBuffer => {
    const b64 = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
};

export const toB64url = (buffer: ArrayBuffer | null | undefined): string => {
    if (!buffer) return '';
    const bytes = new Uint8Array(buffer);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/** The browser's cancel/timeout errors as a readable message. */
export const friendlyError = (error: unknown): Error => {
    const name = error instanceof Error || error instanceof DOMException ? error.name : '';
    if (name === 'NotAllowedError' || name === 'AbortError') {
        return new Error('The passkey request was cancelled or timed out.');
    }
    if (name === 'InvalidStateError') {
        return new Error('This device already has a passkey for your account.');
    }
    if (name === 'SecurityError') {
        return new Error('Passkeys only work on the official panel address.');
    }
    if (name === 'NotSupportedError') {
        return new Error('This device or browser cannot create this kind of passkey.');
    }
    return error instanceof Error ? error : new Error('Something went wrong with the passkey.');
};

interface DescriptorJson {
    id: string;
    type: PublicKeyCredentialType;
    transports?: AuthenticatorTransport[];
}

const descriptors = (list: DescriptorJson[] | undefined): PublicKeyCredentialDescriptor[] =>
    (list ?? []).map((c) => ({ ...c, id: fromB64url(c.id) }));

export async function getPasskeys(): Promise<PasskeyList> {
    const { data } = await http.get(ACCOUNT);
    return { passkeys: data.passkeys, promptDismissed: data.prompt_dismissed, max: data.max };
}

export async function addPasskey(name: string, password: string): Promise<void> {
    const { data: args } = await http.post(`${ACCOUNT}/options`, { password });
    const pk = args.publicKey;

    let credential: Credential | null;
    try {
        credential = await navigator.credentials.create({
            publicKey: {
                ...pk,
                challenge: fromB64url(pk.challenge),
                user: { ...pk.user, id: fromB64url(pk.user.id) },
                excludeCredentials: descriptors(pk.excludeCredentials),
            },
        });
    } catch (error) {
        throw friendlyError(error);
    }
    if (!(credential instanceof PublicKeyCredential)) throw new Error('No passkey was created.');

    const response = credential.response as AuthenticatorAttestationResponse;
    await http.post(ACCOUNT, {
        name,
        client_data_json: toB64url(response.clientDataJSON),
        attestation_object: toB64url(response.attestationObject),
    });
}

export const deletePasskey = (id: number, password: string): Promise<void> =>
    http.delete(`${ACCOUNT}/${id}`, { data: { password } }).then(() => undefined);

export const dismissPasskeyPrompt = (): Promise<void> =>
    http.post(`${ACCOUNT}/dismiss-prompt`).then(() => undefined);

/** A local path to go to after signing in: anything else becomes "/". */
export const safeIntended = (intended: unknown): string =>
    typeof intended === 'string' && intended.startsWith('/') && intended[1] !== '/' && intended[1] !== '\\'
        ? intended
        : '/';

/** Runs the whole sign-in ceremony; resolves with where to go next. */
export async function signInWithPasskey(): Promise<string> {
    await http.get('/sanctum/csrf-cookie');
    const { data: args } = await http.post(`${SIGN_IN}/options`);
    const pk = args.publicKey;

    let credential: Credential | null;
    try {
        credential = await navigator.credentials.get({
            publicKey: {
                ...pk,
                challenge: fromB64url(pk.challenge),
                allowCredentials: descriptors(pk.allowCredentials),
            },
        });
    } catch (error) {
        throw friendlyError(error);
    }
    if (!(credential instanceof PublicKeyCredential)) throw new Error('No passkey was selected.');

    const response = credential.response as AuthenticatorAssertionResponse;
    const { data } = await http.post(`${SIGN_IN}/login`, {
        id: toB64url(credential.rawId),
        client_data_json: toB64url(response.clientDataJSON),
        authenticator_data: toB64url(response.authenticatorData),
        signature: toB64url(response.signature),
        user_handle: toB64url(response.userHandle),
    });

    if (data?.data?.complete !== true) throw new Error('That passkey could not be used to sign in.');
    // Only ever a local path from this panel ("//host" and "/\\host" are protocol-relative).
    return safeIntended(data.data.intended);
}

/** A guess at a name for this device's passkey. */
export const guessDeviceName = (): string => {
    const ua = navigator.userAgent;
    if (/iPhone/.test(ua)) return 'iPhone';
    if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'iPad';
    if (/Android/.test(ua)) return 'Android phone';
    if (/CrOS/.test(ua)) return 'Chromebook';
    if (/Mac/.test(ua)) return 'Mac';
    if (/Windows/.test(ua)) return 'Windows PC';
    if (/Linux/.test(ua)) return 'Linux computer';
    return 'Passkey';
};
