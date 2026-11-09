# ATT&CK coverage and rule metrics

## Coverage matrix (`/coverage`)

Each column is an ATT&CK tactic and each cell a technique. A cell counts your
**enabled rules that compile** whose tags name the technique, for example:

```yaml
tags:
  - attack.initial-access
  - attack.t1190        # technique
  - attack.t1110.001    # sub-technique: also counts toward T1110
```

Cell colours:

| Colour | Meaning |
|---|---|
| grey | no rule |
| light | rules exist, no passing tests |
| medium | at least one rule passes its tests (`tests/rules/<id>/`) |
| dark | tested **and** the rule has fired on real data |

Hover a cell to see its rules. "Show covered only" hides empty techniques.
A tag that is not in the bundled ATT&CK release (revoked, deprecated or a typo)
appears in a warning at the top of the page and as a `rules lint` warning.

### Navigator layer

"Navigator layer (JSON)" downloads a layer file for the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/): choose
*Open Existing Layer → Upload from local*. The score is the number of enabled
rules. The file contains your rule titles, so treat it like any other export.

### Updating ATT&CK

ThreatLens bundles ATT&CK Enterprise v20.0 and never downloads it at runtime.
To move to a newer release (this needs internet access once):

```bash
python scripts/gen_attack_techniques.py --version 21.0
```

Then run the tests and commit the regenerated
`src/threatlens/attack/data/enterprise-attack.json`.

## Rule metrics (`/metrics`)

For every rule: events matched, alerts, suppressed hits, open alerts, and the
verdicts from closed alerts.

- **Precision = TP / (TP + FP).** Benign true positives (authorised activity)
  are not counted against the rule.
- No verdicts yet means no precision ("—"), not 0%.
- **Noisiest rules** lists the rules with the most alerts. Rules below 50%
  precision are highlighted; tune them with a Sigma filter or a suppression
  (see [triage-workflow.md](triage-workflow.md)).

MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
