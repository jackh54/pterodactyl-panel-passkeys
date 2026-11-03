import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Fingerprint, X } from 'lucide-react';
import { Button, Icon, PanelLink } from '@pterodactyl/sdk';
import { dismissPasskeyPrompt, getPasskeys, PASSKEYS_QUERY_KEY, type PasskeyList, passkeysSupported } from './passkeys';

/**
 * One-time dashboard notice that passkeys are available (slot dashboard.before). Shown until the
 * account has a passkey or the notice is dismissed; the dismissal is stored on the account, so it
 * stays gone on every device.
 */
export default function PasskeyPrompt() {
    const supported = passkeysSupported();
    const queryClient = useQueryClient();
    const { data } = useQuery({
        queryKey: PASSKEYS_QUERY_KEY,
        queryFn: getPasskeys,
        enabled: supported,
        retry: false,
        staleTime: 60_000,
    });
    const dismiss = useMutation({
        mutationFn: dismissPasskeyPrompt,
        onMutate: () => {
            queryClient.setQueryData<PasskeyList>(PASSKEYS_QUERY_KEY, (old) =>
                old ? { ...old, promptDismissed: true } : old
            );
        },
    });

    if (!supported || !data || data.passkeys.length > 0 || data.promptDismissed) return null;

    const hide = () => dismiss.mutate();

    return (
        <div
            className={
                'ppk-passkey-prompt ppk:mb-4 ppk:flex ppk:flex-col ppk:gap-4 ppk:rounded-lg ppk:border ppk:border-border ppk:bg-card ppk:px-4 ppk:py-4 ppk:text-card-foreground ppk:sm:flex-row ppk:sm:items-center ppk:sm:px-5'
            }
            role={'region'}
            aria-label={'Passkeys are available'}
        >
            <div className={'ppk:flex ppk:min-w-0 ppk:flex-1 ppk:items-start ppk:gap-3'}>
                <span
                    className={
                        'ppk:flex ppk:h-10 ppk:w-10 ppk:flex-none ppk:items-center ppk:justify-center ppk:rounded-lg ppk:bg-primary/15 ppk:text-primary'
                    }
                >
                    <Icon icon={Fingerprint} className={'ppk:h-5 ppk:w-5'} />
                </span>
                <div className={'ppk:min-w-0'}>
                    <p className={'ppk:text-sm ppk:font-semibold ppk:text-foreground'}>
                        You can now sign in with a passkey
                    </p>
                    <p className={'ppk:mt-0.5 ppk:text-xs ppk:text-muted-foreground'}>
                        Use your fingerprint, face or device PIN instead of your password. It&apos;s faster and it
                        can&apos;t be phished.
                    </p>
                </div>
            </div>
            <div className={'ppk:flex ppk:flex-none ppk:items-center ppk:gap-2'}>
                <PanelLink
                    destination={{ to: '/account', hash: 'passkeys' }}
                    onClick={hide}
                    className={
                        'ppk:inline-flex ppk:h-9 ppk:items-center ppk:rounded-sm ppk:bg-primary ppk:px-4 ppk:text-xs ppk:font-semibold ppk:uppercase ppk:tracking-wide ppk:text-primary-foreground ppk:no-underline ppk:hover:bg-primary/80'
                    }
                >
                    Add a passkey
                </PanelLink>
                <Button.Text size={'small'} onClick={hide} title={'Dismiss'}>
                    <span className={'ppk:inline-flex ppk:items-center ppk:gap-1.5'}>
                        <Icon icon={X} /> Not now
                    </span>
                </Button.Text>
            </div>
        </div>
    );
}
