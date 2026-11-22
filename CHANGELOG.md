# Changelog

## Unreleased

- Fix feeds becoming invalid XML when a vulnerability contains characters XML doesn't allow

## 1.3.3 - 2026-11-15

- Updated Go to 1.27.4, trivy to 0.76.0.

## 1.3.2 - 2026-11-06

- Updated dependencies.

## 1.3.1 - 2026-10-20

- Updated to Go 1.27.3 and dockerbase 1.20261020.1, which distrust the
  compromised eMudhra intermediate CA.

## 1.3.0 - 2026-10-09

- Updated dependencies.

## 1.2.0 - 2026-09-05

- Purser will now try to pull images when docker-save provides
  an incomplete tarball. This happens when the image has been
  pruned.

## 1.1.2 - 2026-02-12 

- Fixed purser only ever waiting to run one scan and then exiting.

## 1.1.1 - 2026-01-11

- Dockerfile now uses env vars for default settings, so they can be
  overridden more easily

## 1.1.0 - 2026-01-07

- If purser can't scan an image, it will now record a vulnerability with the
  details, instead of just exiting and not generating a report.

## 1.0.0 - 2026-01-02

_Initial release_
