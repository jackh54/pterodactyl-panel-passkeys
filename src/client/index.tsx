import './styles.css';
import { definePterodactylExtension } from '@pterodactyl/sdk';
import PasskeySignIn from './auth/PasskeySignIn';
import PasskeyPrompt from './auth/PasskeyPrompt';
import { AccountPasskeys } from './account/PasskeysBox';

// setup() must stay synchronous.
export default definePterodactylExtension({
    setup({ slots }) {
        // "Sign in with a passkey" under the sign-in form.
        slots.register('auth.login.form.after', PasskeySignIn);
        // The one-time "you can add a passkey" notice above the dashboard.
        slots.register('dashboard.before', PasskeyPrompt);
        // The Passkeys card on the account overview, below the panel's own cards.
        slots.register('account.overview.after', AccountPasskeys);
    },
});
