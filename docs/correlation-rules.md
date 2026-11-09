# Correlation rules

> Correlation rules are loaded and listed now; **they run from Phase 4**. This page
> will grow with that phase.

[Sigma v2 correlation rules](https://sigmahq.io/docs/meta/correlations.html)
combine the results of other rules: "10 failed logins from one IP in 5 minutes",
"login success after many failures", and so on. ThreatLens compiles them with
pySigma-backend-sqlite, which supports `event_count`, `value_count`, `temporal`,
`temporal_ordered`, `value_sum` and `value_avg`.

## Referencing rules

A correlation rule lists other rules by their `name` (or `id`) under `rules:`.
The referenced rules can live in any file of your rule set.

```yaml
title: SSH Brute Force From One Address
id: 0e9e0c1c-5b62-4bd1-8c43-0f6f6f5a1a01
correlation:
  type: event_count
  rules:
    - example_ssh_failed_login     # the `name:` of the bundled example rule
  group-by:
    - source.ip
  timespan: 5m
  condition:
    gte: 10
  generate: false
level: high
```

## `generate`: where it goes

In Sigma v2, `generate` is part of the **correlation**. With `generate: true`,
the referenced rules also create their own alerts; with `false` (the default),
only the correlation alerts. Putting `generate: true` on a *base* rule has no
effect. This is a common mistake.
