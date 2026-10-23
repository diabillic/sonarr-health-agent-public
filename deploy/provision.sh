#!/usr/bin/env bash
# One-time (re-runnable) provisioning, run from an admin workstation with:
#   - SSH to the Proxmox host as root (PVE_HOST, default alias "pve")
#   - gh CLI authenticated with admin on the repo
# Creates two unprivileged LXCs (GitHub runner + agent), registers the runner,
# authorises the runner's deploy key on the agent, and sets the AGENT_HOST repo variable.
# Env: PVE_HOST, GH_REPO, GH_BIN, RUNNER_CTID, AGENT_CTID (default auto),
#      plus STORAGE / BRIDGE / VLAN / TEMPLATE_STORAGE passed through to create-lxc.sh.
set -euo pipefail

PVE=${PVE_HOST:-pve}
GH=${GH_BIN:-gh}
HERE=$(cd "$(dirname "$0")" && pwd)
# The repository this clone belongs to (owner/name); override with GH_REPO.
REPO=${GH_REPO:-$(cd "$HERE" && "$GH" repo view --json nameWithOwner --jq .nameWithOwner)}
[[ -n "$REPO" ]] || { echo "set GH_REPO=owner/name" >&2; exit 1; }
RUNNER_NAME=${RUNNER_NAME:-gh-runner}
AGENT_NAME=${AGENT_NAME:-sonarr-agent}
# Public key put in the LXCs' root authorized_keys for admin access.
ADMIN_PUBKEY=${ADMIN_PUBKEY:-$HOME/.ssh/id_ed25519.pub}
REMOTE=/root/sonarr-agent-provision

passthru=""
for v in STORAGE BRIDGE VLAN TEMPLATE_STORAGE DISTRO; do
  [[ -n "${!v:-}" ]] && passthru+="$v=${!v} "
done

kv() { sed -n "s/^$1=//p" <<<"$2" | tail -1; }

echo "==> Copying scripts to $PVE:$REMOTE"
ssh "$PVE" "mkdir -p $REMOTE"
scp -q "$HERE/proxmox/create-lxc.sh" "$HERE/lxc/bootstrap-runner.sh" "$HERE/lxc/bootstrap-agent.sh" \
  "$HERE/lxc/sonarr-agent-install" "$PVE:$REMOTE/"
scp -q "$ADMIN_PUBKEY" "$PVE:$REMOTE/admin.pub"

echo "==> Runner LXC"
out=$(ssh "$PVE" "$passthru MEMORY=2048 CORES=2 DISK=12 bash $REMOTE/create-lxc.sh ${RUNNER_CTID:-auto} $RUNNER_NAME $REMOTE/admin.pub ci")
echo "$out"
RCT=$(kv CTID "$out"); RIP=$(kv IP "$out"); RMAC=$(kv MAC "$out")

echo "==> Agent LXC"
out=$(ssh "$PVE" "$passthru bash $REMOTE/create-lxc.sh ${AGENT_CTID:-auto} $AGENT_NAME $REMOTE/admin.pub media")
echo "$out"
ACT=$(kv CTID "$out"); AIP=$(kv IP "$out"); AMAC=$(kv MAC "$out")

echo "==> Registering GitHub runner on CT $RCT"
token=$("$GH" api -X POST "repos/$REPO/actions/runners/registration-token" --jq .token)
out=$(ssh "$PVE" "pct push $RCT $REMOTE/bootstrap-runner.sh /root/bootstrap-runner.sh && \
  pct exec $RCT -- env LC_ALL=C.UTF-8 GH_URL=https://github.com/$REPO REG_TOKEN=$token RUNNER_NAME=$RUNNER_NAME \
  bash /root/bootstrap-runner.sh")
echo "$out" | grep -v '^DEPLOY_PUBKEY='
DEPLOY_PUBKEY=$(kv DEPLOY_PUBKEY "$out")
[[ -n "$DEPLOY_PUBKEY" ]] || { echo "runner bootstrap did not return a deploy key" >&2; exit 1; }

echo "==> Preparing agent CT $ACT"
ssh "$PVE" "pct push $ACT $REMOTE/bootstrap-agent.sh /root/bootstrap-agent.sh && \
  pct push $ACT $REMOTE/sonarr-agent-install /root/sonarr-agent-install && \
  pct exec $ACT -- env LC_ALL=C.UTF-8 DEPLOY_PUBKEY='$DEPLOY_PUBKEY' INSTALLER=/root/sonarr-agent-install \
  bash /root/bootstrap-agent.sh"

echo "==> Trusting agent host key on runner (read via Proxmox, not over the network)"
hostkey=$(ssh "$PVE" "pct exec $ACT -- cat /etc/ssh/ssh_host_ed25519_key.pub" | cut -d' ' -f1,2)
ssh "$PVE" "pct exec $RCT -- runuser -u runner -- sh -c \"grep -v '^$AIP ' ~/.ssh/known_hosts 2>/dev/null > ~/.ssh/kh.tmp; echo '$AIP $hostkey' >> ~/.ssh/kh.tmp; mv ~/.ssh/kh.tmp ~/.ssh/known_hosts\""

echo "==> Setting repo variable AGENT_HOST=$AIP"
"$GH" variable set AGENT_HOST --repo "$REPO" --body "$AIP"

cat <<EOF

Done.
  Runner: CT $RCT  $RUNNER_NAME  $RIP  MAC $RMAC
  Agent:  CT $ACT  $AGENT_NAME  $AIP  MAC $AMAC
Add DHCP reservations for both MACs so these IPs stay fixed.
EOF
