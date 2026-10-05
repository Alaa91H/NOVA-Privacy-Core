# Firewall Design

NOVA uses nftables as the single firewall/NAT policy engine.

## Default policy

```text
INPUT   DROP
FORWARD DROP
OUTPUT  DROP
```

The generated policy is validated with `nft -c` and then applied as one complete ruleset. NOVA does not flush the firewall and rebuild it piecemeal.

## Public ingress

Intended public ingress is limited to:

- the AmneziaWG UDP port;
- a temporary source-restricted SSH bootstrap rule.

After a verified management-peer handshake, `privacyctl lockdown` removes the temporary public SSH rule.

## Management

SSH is allowed only from tunnel IPs explicitly marked as management peers.

## Forwarding

Forwarding from authenticated tunnel address ranges to WAN is allowed, with NAT masquerade. LOCKDOWN peer addresses are dropped before forwarding.

DoT/DoQ port 853 from tunnel peers is blocked to discourage resolver bypass.

## IPv6

The default one-VPS design does not forward IPv6. Client profiles still claim `::/0`, so unsupported IPv6 traffic enters the tunnel and fails closed rather than using the local ISP directly.
