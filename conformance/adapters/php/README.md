# PHP adapter

Backed by [mpp-php](https://github.com/michaelhairetis/mpp-php).

```bash
composer install
echo '{"schema":1,"op":"base64url.encode","input":{"text":"hi"}}' | php adapter.php
```

Requires PHP 8.2+.

The harness carries a challenge `request` as a decoded object while the SDK holds it in wire form,
so the two are translated here. `credential.format` emits canonical JSON, so challenge keys come
back sorted rather than in input order, compared semantically.

Not yet advertised: `http.payment_request`, `server.verify`, and the `tempo.*` and `stripe.*`
operations. Those need settlement paths the SDK does not implement yet.
