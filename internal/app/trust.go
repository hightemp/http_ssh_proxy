package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/sshmanager"

	"golang.org/x/crypto/ssh/knownhosts"
)

const trustHostKeyTimeout = 30 * time.Second

// errHostKeyNotTrusted reports that the operator declined the presented key.
var errHostKeyNotTrusted = errors.New("host key was not added")

type hostKeyTruster struct {
	inspect func(context.Context, *config.Config) (*sshmanager.HostKeyInspection, error)
	trust   func(*sshmanager.HostKeyInspection) (bool, error)
}

// TrustHostKey shows the host key presented by the configured SSH server and,
// after confirmation on in (or immediately when assumeYes is set), adds it to
// ssh_known_hosts_file. Keys that conflict with existing entries are refused.
func TrustHostKey(ctx context.Context, cfg *config.Config, in io.Reader, out io.Writer, assumeYes bool) error {
	return hostKeyTruster{
		inspect: sshmanager.InspectHostKey,
		trust:   sshmanager.TrustHostKey,
	}.run(ctx, cfg, in, out, assumeYes)
}

func (t hostKeyTruster) run(ctx context.Context, cfg *config.Config, in io.Reader, out io.Writer, assumeYes bool) error {
	if strings.TrimSpace(cfg.SSHKnownHostsFile) == "" {
		return errors.New("-trust-host-key requires ssh_known_hosts_file in the configuration")
	}

	ctx, cancel := context.WithTimeout(ctx, trustHostKeyTimeout)
	defer cancel()
	inspection, err := t.inspect(ctx, cfg)
	if err != nil {
		return fmt.Errorf("inspect SSH host key: %w", err)
	}

	if _, err := fmt.Fprintf(out, "SSH server %s presented %s key %s\n",
		inspection.Address, inspection.Key.Type(), inspection.Fingerprint()); err != nil {
		return err
	}
	switch inspection.Status {
	case sshmanager.HostKeyKnown:
		_, err := fmt.Fprintf(out, "Key is already trusted in %s\n", inspection.KnownHostsFile)
		return err
	case sshmanager.HostKeyRejected:
		return fmt.Errorf("%w; if the key change is expected, remove the old entries "+
			"(ssh-keygen -R %s -f %s) and run -trust-host-key again",
			inspection.Err, knownhosts.Normalize(inspection.Address), inspection.KnownHostsFile)
	}

	if !assumeYes {
		if _, err := fmt.Fprintf(out, "Verify this fingerprint through a trusted channel. Add it to %s? [y/N]: ",
			inspection.KnownHostsFile); err != nil {
			return err
		}
		answer, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read confirmation: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
		default:
			return errHostKeyNotTrusted
		}
	}

	added, err := t.trust(inspection)
	if err != nil {
		return fmt.Errorf("add SSH host key: %w", err)
	}
	if !added {
		_, err := fmt.Fprintf(out, "Key is already trusted in %s\n", inspection.KnownHostsFile)
		return err
	}
	_, err = fmt.Fprintf(out, "Added %s key for %s to %s\n",
		inspection.Key.Type(), knownhosts.Normalize(inspection.Address), inspection.KnownHostsFile)
	return err
}
