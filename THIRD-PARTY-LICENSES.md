# Third-Party Licenses

This plugin bundles third-party libraries via Composer in the `vendor/` directory.

## Included libraries

- `league/oauth2-server` (MIT)
- `guzzlehttp/psr7` (MIT)
- `ralouphie/getallheaders` (MIT)
- `lcobucci/jwt` (BSD-3-Clause)
- `defuse/php-encryption` (MIT)
- `psr/*` interface packages (MIT)
- `automattic/jetpack-autoloader` (GPL-2.0-or-later)
- `wordpress/abilities-api` (GPL-2.0-or-later)
- `wordpress/mcp-adapter` (GPL-2.0-or-later)

Development dependencies are not required at runtime and should not be shipped in a WordPress.org release package.

## Source of truth

Authoritative license metadata is available in:

- `composer.lock`
- each package `composer.json`
- each package `LICENSE`/`LICENSE.txt` file in `vendor/`
