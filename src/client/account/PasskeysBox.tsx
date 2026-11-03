import React, { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Fingerprint, KeyRound, Trash2 } from 'lucide-react';
import { Button, ContentBox, Dialog, httpErrorToHuman, Icon, Input, Label, toast } from '@pterodactyl/sdk';
import {
    addPasskey,
    deletePasskey,
    getPasskeys,
    guessDeviceName,
    type Passkey,
    PASSKEYS_QUERY_KEY,
    passkeysSupported,
} from '../auth/passkeys';

const dateFormat = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' });

function relative(iso: string): string {
    const seconds = (new Date(iso).getTime() - Date.now()) / 1000;
    const units: [Intl.RelativeTimeFormatUnit, number][] = [
        ['year', 31_536_000],
        ['month', 2_592_000],
        ['day', 86_400],
        ['hour', 3_600],
        ['minute', 60],
    ];
    const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
    for (const [unit, size] of units) {
        if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit);
    }
    return 'just now';
}

const notifyError = (title: string, error: unknown) => {
    console.error(error);
    toast.error(title, { description: httpErrorToHuman(error), duration: 8000 });
};

function PasswordField({ id, value, onChange }: { id: string; value: string; onChange: (value: string) => void }) {
    return (
        <div className={'ppk:mt-4'}>
            <Label htmlFor={id}>Current password</Label>
            <Input
                id={id}
                type={'password'}
                autoComplete={'current-password'}
                value={value}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.currentTarget.value)}
                required
            />
        </div>
    );
}

function AddPasskeyDialog({ open, onClose, onAdded }: { open: boolean; onClose: () => void; onAdded: () => void }) {
    const [name, setName] = useState(guessDeviceName);
    const [password, setPassword] = useState('');
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        if (open) {
            setName(guessDeviceName());
            setPassword('');
            setBusy(false);
        }
    }, [open]);

    const submit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        e.stopPropagation();
        if (busy || !password) return;
        setBusy(true);
        try {
            await addPasskey(name.trim() || 'Passkey', password);
            toast.success('Passkey added. You can now sign in with it.');
            onAdded();
            onClose();
        } catch (error) {
            setPassword('');
            notifyError('Unable to add the passkey', error);
        } finally {
            setBusy(false);
        }
    };

    return (
        <Dialog
            open={open}
            onClose={onClose}
            preventExternalClose={busy}
            hideCloseIcon={busy}
            title={'Add a passkey'}
            description={'Confirm your password, then follow the prompt from your device or password manager.'}
        >
            <form id={'ppk-add-passkey'} className={'ppk:mt-2'} onSubmit={submit}>
                <Label htmlFor={'ppk-passkey-name'}>Name</Label>
                <Input
                    id={'ppk-passkey-name'}
                    maxLength={64}
                    value={name}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setName(e.currentTarget.value)}
                    required
                />
                <PasswordField id={'ppk-passkey-add-password'} value={password} onChange={setPassword} />
                <Dialog.Footer>
                    <Button.Text onClick={onClose} disabled={busy}>
                        Cancel
                    </Button.Text>
                    <Button type={'submit'} form={'ppk-add-passkey'} disabled={busy || !password} isLoading={busy}>
                        Continue
                    </Button>
                </Dialog.Footer>
            </form>
        </Dialog>
    );
}

function RemovePasskeyDialog({ passkey, onClose, onRemoved }: { passkey: Passkey | null; onClose: () => void; onRemoved: () => void }) {
    const [password, setPassword] = useState('');
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        setPassword('');
        setBusy(false);
    }, [passkey]);

    const submit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        e.stopPropagation();
        if (!passkey || busy || !password) return;
        setBusy(true);
        try {
            await deletePasskey(passkey.id, password);
            toast.success(`Removed the passkey "${passkey.name}".`);
            onRemoved();
            onClose();
        } catch (error) {
            setPassword('');
            notifyError('Unable to remove the passkey', error);
        } finally {
            setBusy(false);
        }
    };

    return (
        <Dialog
            open={passkey !== null}
            onClose={onClose}
            preventExternalClose={busy}
            hideCloseIcon={busy}
            title={'Remove passkey'}
            description={passkey ? `Enter your password to remove "${passkey.name}". It will no longer sign you in.` : ''}
        >
            <form id={'ppk-remove-passkey'} onSubmit={submit}>
                <PasswordField id={'ppk-passkey-remove-password'} value={password} onChange={setPassword} />
                <Dialog.Footer>
                    <Button.Text onClick={onClose} disabled={busy}>
                        Cancel
                    </Button.Text>
                    <Button.Danger type={'submit'} form={'ppk-remove-passkey'} disabled={busy || !password} isLoading={busy}>
                        Remove
                    </Button.Danger>
                </Dialog.Footer>
            </form>
        </Dialog>
    );
}

/** Account > Passkeys (slot account.overview.after, anchor #passkeys). */
export default function PasskeysBox() {
    const supported = passkeysSupported();
    const queryClient = useQueryClient();
    const { data, error, isPending, refetch } = useQuery({
        queryKey: PASSKEYS_QUERY_KEY,
        queryFn: getPasskeys,
        retry: false,
    });
    const [adding, setAdding] = useState(false);
    const [removing, setRemoving] = useState<Passkey | null>(null);

    const refresh = () => void queryClient.invalidateQueries({ queryKey: PASSKEYS_QUERY_KEY });

    useEffect(() => {
        if (window.location.hash !== '#passkeys' || isPending) return;
        const timer = window.setTimeout(
            () => document.getElementById('passkeys')?.scrollIntoView({ behavior: 'smooth', block: 'center' }),
            150
        );
        return () => window.clearTimeout(timer);
    }, [isPending]);

    const passkeys = data?.passkeys ?? [];
    const full = data ? passkeys.length >= data.max : false;

    return (
        <ContentBox id={'passkeys'} title={'Passkeys'} className={'ppk-passkeys ppk:scroll-mt-24'}>
            <p className={'ppk:text-sm'}>
                Sign in with your fingerprint, face or device PIN instead of your password. Passkeys can&apos;t be
                phished and count as two-step verification on their own.
            </p>
            {!supported && (
                <p className={'ppk:mt-3 ppk:text-sm ppk:text-warning'}>This browser does not support passkeys.</p>
            )}

            <div className={'ppk:mt-4 ppk:space-y-2'}>
                {isPending ? (
                    <p className={'ppk:text-sm ppk:text-muted-foreground'}>Loading...</p>
                ) : error ? (
                    <div className={'ppk:flex ppk:items-center ppk:gap-3 ppk:text-sm ppk:text-destructive'}>
                        <span>{httpErrorToHuman(error)}</span>
                        <Button.Text size={'xsmall'} onClick={() => void refetch()}>
                            Retry
                        </Button.Text>
                    </div>
                ) : passkeys.length === 0 ? (
                    <p className={'ppk:text-sm ppk:text-muted-foreground'}>You don&apos;t have any passkeys yet.</p>
                ) : (
                    passkeys.map((p) => (
                        <div
                            key={p.id}
                            className={
                                'ppk:flex ppk:items-center ppk:gap-3 ppk:rounded-sm ppk:border ppk:border-border ppk:bg-popover ppk:px-3 ppk:py-2.5'
                            }
                        >
                            <Icon icon={KeyRound} className={'ppk:flex-none ppk:text-muted-foreground'} />
                            <div className={'ppk:min-w-0 ppk:flex-1'}>
                                <p className={'ppk:truncate ppk:text-sm ppk:font-semibold ppk:text-foreground'}>
                                    {p.name}
                                    {p.synced && (
                                        <span
                                            className={
                                                'ppk:ml-2 ppk:rounded-sm ppk:bg-secondary ppk:px-1.5 ppk:py-0.5 ppk:text-[0.65rem] ppk:font-normal ppk:uppercase ppk:tracking-wide ppk:text-muted-foreground'
                                            }
                                            title={'Synced between your devices by your password manager or platform'}
                                        >
                                            synced
                                        </span>
                                    )}
                                </p>
                                <p className={'ppk:text-xs ppk:text-muted-foreground'}>
                                    Added {dateFormat.format(new Date(p.created_at))} &middot;{' '}
                                    {p.last_used_at ? `last used ${relative(p.last_used_at)}` : 'never used'}
                                </p>
                            </div>
                            <button
                                type={'button'}
                                title={'Remove passkey'}
                                aria-label={`Remove the passkey ${p.name}`}
                                onClick={() => setRemoving(p)}
                                className={
                                    'ppk:flex ppk:h-9 ppk:w-9 ppk:flex-none ppk:items-center ppk:justify-center ppk:rounded-sm ppk:text-muted-foreground ppk:transition-colors ppk:hover:bg-destructive/10 ppk:hover:text-destructive'
                                }
                            >
                                <Icon icon={Trash2} />
                            </button>
                        </div>
                    ))
                )}
            </div>

            {supported && (
                <div className={'ppk:mt-6'}>
                    <Button onClick={() => setAdding(true)} disabled={!data || full}>
                        <span className={'ppk:inline-flex ppk:items-center ppk:gap-2'}>
                            <Icon icon={Fingerprint} /> Add a passkey
                        </span>
                    </Button>
                    {full && (
                        <p className={'ppk:mt-2 ppk:text-xs ppk:text-muted-foreground'}>
                            You have the maximum of {data?.max} passkeys. Remove one to add another.
                        </p>
                    )}
                </div>
            )}

            <AddPasskeyDialog open={adding} onClose={() => setAdding(false)} onAdded={refresh} />
            <RemovePasskeyDialog passkey={removing} onClose={() => setRemoving(null)} onRemoved={refresh} />
        </ContentBox>
    );
}

/** The account overview slot: the Passkeys box below the core cards, two columns wide on large screens. */
export function AccountPasskeys() {
    return (
        <div className={'ppk-account-security ppk:mb-10 ppk:grid ppk:grid-cols-1 ppk:gap-8 ppk:lg:grid-cols-3'}>
            <div className={'ppk:lg:col-span-2'}>
                <PasskeysBox />
            </div>
        </div>
    );
}
