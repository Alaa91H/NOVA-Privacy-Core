# Deployment

## Target

Baseline: Debian 13 stable/minimal on an Oracle Cloud VM with approximately 1 vCPU and 1 GB RAM.

## Oracle network prerequisite

The cloud Security List / NSG exists **outside** the guest firewall. NOVA cannot change it through this repository.

Before installation:

1. Restrict TCP/22 to the administrator's current public IP.
2. Permit the chosen NOVA AmneziaWG UDP port (default 51820) from the client networks that need to connect.
3. Do not expose DNS/53, DoT/853, AdGuard UI ports, Unbound, or internal management ports to the Internet.

Keep an Oracle console/recovery method available before firewall changes.

## Install

From an already key-authenticated SSH session:

```bash
git clone https://github.com/Alaa91H/NOVA-Privacy-Core.git
cd NOVA-Privacy-Core
sudo NOVA_WAN_IF=ens3 bash ./scripts/install.sh
```

If the WAN interface differs, use the actual default-route interface:

```bash
ip -4 route show default
```

The installer captures the current SSH source as a temporary host-firewall exception. Do not close the session yet.

## First management peer

```bash
sudo privacyctl peer add laptop PRIVATE --management
```

Import the generated root-only client profile from:

```text
/root/nova-peers/laptop.conf
```

Connect, then verify:

```bash
sudo privacyctl status
sudo privacyctl health
```

From the connected management peer, remove temporary public SSH access:

```bash
sudo privacyctl lockdown
```

The command refuses to remove the bootstrap SSH rule unless a management peer has completed a recent handshake.

## Additional peers

```bash
sudo privacyctl peer add phone PRIVATE
sudo privacyctl peer add tablet STRICT
sudo privacyctl peer add bank COMPAT
```

Each peer gets a unique keypair, PSK, and tunnel IP.

## After importing a client profile

Delete exported client private-key material from the server when you no longer need it:

```bash
sudo rm -f /root/nova-peers/phone.conf /root/nova-peers/phone.qr.png
```

The server registry keeps the public key and PSK required for operation, not the client's private key.
