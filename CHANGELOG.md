# Changelog

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
