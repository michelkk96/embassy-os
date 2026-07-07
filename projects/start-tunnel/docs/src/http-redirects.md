# HTTP Redirects

StartTunnel runs an **HTTP→HTTPS redirect** on port `80` of every public IPv4 address your VPS holds. A plain `http://` request to one of these addresses is answered with a redirect to the same host over `https://`, so visitors who leave off the scheme still land on your TLS service instead of getting a connection error.

These redirects are **on by default** — on a fresh install and after an update, every public IPv4 gets one automatically. You can turn any of them off, and your choice persists.

## Where they run

A redirect binds a lightweight listener directly on `<public-IPv4>:80` on the tunnel host. Only **public** IPv4 addresses are eligible (loopback and private/RFC1918 ranges are skipped) — the same set the web UI lists. IPv6 is handled separately: the `80 → 443` upgrade for a device's IPv6 address is a [pinhole](./port-forwarding.md) port translation, not one of these listeners.

## Mutually exclusive with a port-80 forward

A redirect and a [port forward](./port-forwarding.md) cannot both own port 80 on the same IP. The forward always wins: if port 80 on an address is forwarded (manually or automatically via PCP/UPnP), the redirect on that address **yields** and stops listening. Remove the port-80 forward and the redirect resumes on its own (unless you turned it off).

## Managing them in the UI

On the `Port Forwards` page, the **HTTP Redirects** card lists every public IPv4 with a checkbox:

- **Checked** — the port-80 HTTP→HTTPS redirect is running on that address.
- **Unchecked** — you have turned it off; port 80 there simply refuses plain HTTP.
- **Disabled (greyed) checkbox** — a port forward currently occupies port 80 on that address, so the redirect is yielding. Remove the forward to re-enable the redirect.

## Managing them from the CLI

```bash
# Show the redirect status of every public IPv4
start-tunnel http-redirect list

# Turn the redirect off for one address (omit --enabled)
start-tunnel http-redirect set-enabled 203.0.113.10

# Turn it back on
start-tunnel http-redirect set-enabled 203.0.113.10 --enabled
```

See the [CLI reference](./cli-reference.md#http-redirects) for details.
