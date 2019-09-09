package action

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/cui"
	"github.com/gopasspw/gopass/pkg/out"
	"github.com/gopasspw/gopass/pkg/store"
	"github.com/gopasspw/gopass/pkg/store/sub"
	"github.com/gopasspw/gopass/pkg/termio"
	"github.com/pkg/errors"

	"github.com/urfave/cli"
)

var (
	removalWarning = `


@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@   WARNING: REMOVING A USER WILL NOT REVOKE ACCESS FROM OLD REVISONS!   @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
THE USER %s WILL STILL BE ABLE TO ACCESS ANY OLD COPY OF THE STORE AND
ANY OLD REVISION HE HAD ACCESS TO.

ANY CREDENTIALS THIS USER HAD ACCESS TO NEED TO BE CONSIDERED COMPROMISED
AND SHOULD BE REVOKED.

This feature is only meant for revoking access to any added or changed
credentials.

`
)

// RecipientsPrint prints all recipients per store
func (s *Action) RecipientsPrint(ctx context.Context, c *cli.Context) error {
	out.Cyan(ctx, "Hint: run 'gopass sync' to import any missing public keys")

	tree, err := s.Store.RecipientsTree(ctx, true)
	if err != nil {
		return ExitError(ctx, ExitList, err, "failed to list recipients: %s", err)
	}

	fmt.Fprintln(stdout, tree.Format(0))
	return nil
}

// RecipientsPrintExpiration prints all recipients whose key has expired or will expire before the threshold provided.
func (s *Action) RecipientsPrintExpiration(ctx context.Context, c *cli.Context) error {
	store := c.String("store")
	warnThreshold := c.Duration("warn-threshold")
	expirationErr := errors.New("key(s) expired/expiring")
	hasErr := false

	crypto := s.Store.Crypto(ctx, store)
	if crypto == nil {
		return errors.New("nil crypto backend")
	}

	for _, recipient := range s.Store.ListRecipients(ctx, store) {
		r := "0x" + recipient
		expiration, err := crypto.ExpirationDateFromKey(ctx, recipient)
		if err != nil {
			return err
		}
		name := crypto.NameFromKey(ctx, recipient)
		if notice, warn := renderExpirationNotice(expiration, warnThreshold); warn {
			fmt.Fprintf(stdout, "%s (%s) %s\n", r, name, notice)
			hasErr = true
		}
	}
	if hasErr {
		return expirationErr
	}
	return nil
}

func renderExpirationNotice(expirationDate time.Time, warnThreshold time.Duration) (notice string, warn bool) {
	// some keys are set to be valid forever
	if !expirationDate.IsZero() {
		if time.Now().After(expirationDate) {
			return fmt.Sprintf("expired at %s", expirationDate), true
		}
		if expirationDate.Before(time.Now().Add(warnThreshold)) {
			return fmt.Sprintf("expiring in ~%s at %s", time.Until(expirationDate).Truncate(time.Hour), expirationDate), true
		}
	}
	return "", false
}

// RecipientsComplete will print a list of recipients for bash
// completion
func (s *Action) RecipientsComplete(ctx context.Context, c *cli.Context) {
	tree, err := s.Store.RecipientsTree(out.WithHidden(ctx, true), false)
	if err != nil {
		fmt.Fprintln(stdout, err)
		return
	}

	for _, v := range tree.List(0) {
		fmt.Fprintln(stdout, v)
	}
}

// RecipientsAdd adds new recipients
func (s *Action) RecipientsAdd(ctx context.Context, c *cli.Context) error {
	store := c.String("store")
	force := c.Bool("force")
	added := 0

	// select store
	if store == "" {
		store = cui.AskForStore(ctx, s.Store)
	}

	crypto := s.Store.Crypto(ctx, store)

	// select recipient
	recipients := []string(c.Args())
	if len(recipients) < 1 {
		r, err := s.recipientsSelectForAdd(ctx, store)
		if err != nil {
			return err
		}
		recipients = r
	}

	for _, r := range recipients {
		keys, err := crypto.FindPublicKeys(ctx, r)
		if err != nil {
			out.Cyan(ctx, "WARNING: Failed to list public key '%s': %s", r, err)
			if !force {
				continue
			}
			keys = []string{r}
		}
		if len(keys) < 1 && !force {
			out.Cyan(ctx, "Warning: No matching valid key found. If the key is in your keyring you may need to validate it.")
			out.Cyan(ctx, "If this is your key: gpg --edit-key %s; trust (set to ultimate); quit", r)
			out.Cyan(ctx, "If this is not your key: gpg --edit-key %s; lsign; trust; save; quit", r)
			out.Cyan(ctx, "You may need to run 'gpg --update-trustdb' afterwards")
			continue
		}

		recp := r
		if len(keys) > 0 {
			recp = crypto.Fingerprint(ctx, keys[0])
		}

		if !termio.AskForConfirmation(ctx, fmt.Sprintf("Do you want to add '%s' as a recipient to the store '%s'?", crypto.FormatKey(ctx, recp), store)) {
			continue
		}

		if err := s.Store.AddRecipient(ctxutil.WithNoConfirm(ctx, true), store, recp); err != nil {
			return ExitError(ctx, ExitRecipients, err, "failed to add recipient '%s': %s", r, err)
		}
		added++
	}
	if added < 1 {
		return ExitError(ctx, ExitUnknown, nil, "no key added")
	}

	out.Green(ctx, "\nAdded %d recipients", added)
	out.Cyan(ctx, "You need to run 'gopass sync' to push these changes")
	return nil
}

// RecipientsRemove removes recipients
func (s *Action) RecipientsRemove(ctx context.Context, c *cli.Context) error {
	store := c.String("store")
	force := c.Bool("force")
	removed := 0

	// select store
	if store == "" {
		store = cui.AskForStore(ctx, s.Store)
	}

	crypto := s.Store.Crypto(ctx, store)

	// select recipient
	recipients := []string(c.Args())
	if len(recipients) < 1 {
		rs, err := s.recipientsSelectForRemoval(ctx, store)
		if err != nil {
			return err
		}
		recipients = rs
	}

	for _, r := range recipients {
		kl, err := crypto.FindPrivateKeys(ctx, r)
		if err == nil {
			if len(kl) > 0 {
				if !termio.AskForConfirmation(ctx, fmt.Sprintf("Do you want to remove yourself (%s) from the recipients?", r)) {
					continue
				}
			}
		}

		keys, err := crypto.FindPublicKeys(ctx, r)
		if err != nil {
			out.Cyan(ctx, "WARNING: Failed to list public key '%s': %s", r, err)
			if !force {
				continue
			}
			keys = []string{r}
		}
		if len(keys) < 1 && !force {
			out.Cyan(ctx, "Warning: No matching valid key found. If the key is in your keyring you may need to validate it.")
			out.Cyan(ctx, "If this is your key: gpg --edit-key %s; trust (set to ultimate); quit", r)
			out.Cyan(ctx, "If this is not your key: gpg --edit-key %s; lsign; trust; save; quit", r)
			out.Cyan(ctx, "You may need to run 'gpg --update-trustdb' afterwards")
			continue
		}

		recp := r
		if len(keys) > 0 {
			recp = crypto.Fingerprint(ctx, keys[0])
		}

		if err := s.Store.RemoveRecipient(ctxutil.WithNoConfirm(ctx, true), store, recp); err != nil {
			return ExitError(ctx, ExitRecipients, err, "failed to remove recipient '%s': %s", recp, err)
		}
		fmt.Fprintf(stdout, removalWarning, r)
		removed++
	}
	if removed < 1 {
		return ExitError(ctx, ExitUnknown, nil, "no key removed")
	}

	out.Green(ctx, "\nRemoved %d recipients", removed)
	out.Cyan(ctx, "You need to run 'gopass sync' to push these changes")
	return nil
}

// RecipientsUpdate will recompute and update any changed recipients list checksums
func (s *Action) RecipientsUpdate(ctx context.Context, c *cli.Context) error {
	changed := 0

	mps := s.Store.MountPoints()
	sort.Sort(store.ByPathLen(mps))
	for _, alias := range append(mps, "") {
		subs, err := s.Store.GetSubStore(alias)
		if err != nil || subs == nil {
			continue
		}
		recp, err := subs.GetRecipients(ctx, "")
		if err != nil {
			if err != sub.ErrRecipientChecksumChanged {
				return err
			}
		}
		if err == nil && s.cfg.GetRecipientHash(alias, subs.Crypto().IDFile()) != "" {
			continue
		}
		if alias == "" {
			alias = "<root>"
		}
		out.Cyan(ctx, "Please confirm Recipients for %s:", alias)
		for _, r := range recp {
			out.Print(ctx, "- %s", subs.Crypto().FormatKey(ctx, r))
		}
		if !termio.AskForConfirmation(ctx, fmt.Sprintf("Do you trust these recipients for %s?", alias)) {
			continue
		}
		if err := subs.SetRecipients(ctx, recp); err != nil {
			return err
		}
		out.Print(ctx, "")
		changed++
	}

	if changed > 0 {
		out.Green(ctx, "Updated %d stores", changed)
	} else {
		out.Green(ctx, "Nothing to do")
	}

	return nil
}

func (s *Action) recipientsSelectForRemoval(ctx context.Context, store string) ([]string, error) {
	crypto := s.Store.Crypto(ctx, store)

	ids := s.Store.ListRecipients(ctx, store)
	choices := make([]string, 0, len(ids))
	for _, id := range ids {
		choices = append(choices, crypto.FormatKey(ctx, id))
	}
	if len(choices) < 1 {
		return nil, nil
	}

	act, sel := cui.GetSelection(ctx, "Remove recipient -", "<↑/↓> to change the selection, <→> to remove this recipient, <ESC> to quit", choices)
	switch act {
	case "default":
		fallthrough
	case "show":
		return []string{ids[sel]}, nil
	default:
		return nil, ExitError(ctx, ExitAborted, nil, "user aborted")
	}
}

func (s *Action) recipientsSelectForAdd(ctx context.Context, store string) ([]string, error) {
	crypto := s.Store.Crypto(ctx, store)

	choices := []string{}
	kl, _ := crypto.FindPublicKeys(ctx)
	for _, key := range kl {
		choices = append(choices, crypto.FormatKey(ctx, key))
	}
	if len(choices) < 1 {
		return nil, nil
	}

	act, sel := cui.GetSelection(ctx, "Add Recipient -", "<↑/↓> to change the selection, <→> to add this recipient, <ESC> to quit", choices)
	switch act {
	case "default":
		fallthrough
	case "show":
		return []string{kl[sel]}, nil
	default:
		return nil, ExitError(ctx, ExitAborted, nil, "user aborted")
	}
}
