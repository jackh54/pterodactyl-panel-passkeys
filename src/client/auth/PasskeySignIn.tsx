import { useState } from 'react';
import { Fingerprint } from 'lucide-react';
import { Button, httpErrorToHuman, Icon, toast } from '@pterodactyl/sdk';
import { passkeysSupported, signInWithPasskey } from './passkeys';

/** "Sign in with a passkey" under the core login form (slot auth.login.form.after). */
export default function PasskeySignIn() {
    const [busy, setBusy] = useState(false);

    if (!passkeysSupported()) return null;

    const onClick = async () => {
        if (busy) return;
        setBusy(true);
        try {
            window.location.assign(await signInWithPasskey());
        } catch (error) {
            console.error(error);
            setBusy(false);
            toast.error('Unable to sign in with a passkey', { description: httpErrorToHuman(error), duration: 8000 });
        }
    };

    return (
        <div className={'ppk-passkey-signin ppk:mt-6'}>
            <div className={'ppk:mb-6 ppk:flex ppk:items-center ppk:gap-3'} aria-hidden={'true'}>
                <div className={'ppk:h-px ppk:flex-1 ppk:bg-border'} />
                <span className={'ppk:text-xs ppk:uppercase ppk:tracking-widest ppk:text-muted-foreground'}>
                    or
                </span>
                <div className={'ppk:h-px ppk:flex-1 ppk:bg-border'} />
            </div>
            <Button
                type={'button'}
                size={'xlarge'}
                color={'grey'}
                isSecondary
                disabled={busy}
                aria-busy={busy || undefined}
                onClick={onClick}
            >
                <span className={'ppk:inline-flex ppk:items-center ppk:justify-center ppk:gap-2'}>
                    <Icon icon={Fingerprint} />
                    {busy ? 'Waiting for your passkey...' : 'Sign in with a passkey'}
                </span>
            </Button>
        </div>
    );
}
