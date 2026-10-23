#!/usr/bin/env bash
# Runs INSIDE the agent LXC as root. Prepares it to receive deploys from the runner.
# Env: DEPLOY_PUBKEY (runner's deploy key), INSTALLER (path to pushed sonarr-agent-install)
#
# The `deploy` user can only stage files and run the root-owned installer via sudo;
# the installer writes the systemd unit itself, so a deploy can't change what runs as root.
set -euo pipefail
: "${DEPLOY_PUBKEY:?}" "${INSTALLER:?}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv rsync sudo openssh-server ca-certificates >/dev/null
systemctl enable --now ssh >/dev/null

id sonarr-agent >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sonarr-agent --shell /usr/sbin/nologin sonarr-agent
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy

install -d -m 700 -o deploy -g deploy /home/deploy/.ssh /home/deploy/staging
echo "$DEPLOY_PUBKEY" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

install -d -m 755 /opt/sonarr-agent
install -d -m 750 -g sonarr-agent /etc/sonarr-agent
install -m 750 -o root -g root "$INSTALLER" /usr/local/sbin/sonarr-agent-install

echo 'deploy ALL=(root) NOPASSWD: /usr/local/sbin/sonarr-agent-install' > /etc/sudoers.d/sonarr-agent-deploy
chmod 440 /etc/sudoers.d/sonarr-agent-deploy
visudo -cf /etc/sudoers.d/sonarr-agent-deploy >/dev/null

echo "agent LXC ready"
