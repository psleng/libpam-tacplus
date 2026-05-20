# AGENTS.md

## Project purpose

PAM module providing TACACS+ authentication, authorization, and accounting for VyOS logins, plus the `libtac` TACACS+ protocol library and the `tacc` CLI client. Pairs with `libnss-tacplus` (NSS lookups) and `libtacplus-map` (user mapping) to deliver TACACS+ login on VyOS.

## Tech stack

- C, GNU autotools (`configure.ac`, `Makefile.am`, `auto.sh`).
- Debian packaging in `debian/` (debhelper >= 9, `libpam-dev`, `dh-autoreconf`, `autoconf-archive`, `libaudit-dev`).
- Builds Debian packages: `libpam-tacplus`, `libpam-tacplus-dev`, `libtac2`, `libtac2-bin`, `libtac-dev`.
- License: GPL-2.0 (per `COPYING`).

## Build / test / run

```sh
./auto.sh                 # autoreconf (generates./configure)
./configure
make
dpkg-buildpackage -us -uc
```

`tacc` is a small CLI client useful for manual testing (`tacc.1` man page). No bundled unit tests; Coverity scan badge in README references upstream.

## Repository layout

- `pam_tacplus.c`, `pam_tacplus.h`, `support.c/h` — PAM module.
- `libtac/` — protocol library (produces `libtac2`).
- `tacc.c`, `tacc.1` — CLI client.
- `tacplus_servers`, `tacplus_servers.5`, `Pam.d.common-example`, `sample.pam` — config + examples.
- `debian/`, `pam_tacplus.spec.in` — packaging.

## Cross-repo context

Authentication building block of the VyOS image. Provides the `libtac` library that `libnss-tacplus` links against, and the PAM module that `libtacplus-map` complements for `/etc/passwd`-less TACACS+ logins. Built via the internal build-packages workflow; consumed by `vyos/vyos-build`.

## Conventions

- Default branch `master`. LTS branches when needed.
- Commit / PR title format: `component: T12345: description` (Phorge task ID at https://vyos.dev).
- Treat as upstream-vendored: minimise diffs against the upstream `pam_tacplus`.

## Notes for future contributors

- The `libtac/` subdirectory is the TACACS+ protocol library and is shipped as a separately versioned `libtac2` Debian package — bump the soname carefully.
- README is upstream's; VyOS-specific behaviour is encoded only by the build flags and patches applied here.
