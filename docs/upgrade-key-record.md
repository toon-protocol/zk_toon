# The upgrade key's holders' record

Who holds each vault's key shares, its check log, destruction statements and replacements. The procedures
are in `docs/upgrade-key-holders.md` and the rules in ADR 0013.

No ceremony has been run yet, so no vault is listed. Each vault gets a section like this:

```
### Vault <address> (<network>), ceremony <date>

| Role | Holder | Communication key fingerprint | Since |
|---|---|---|---|
| Operator | … | … | … |
| TOON team | … | … | … |
| Independent | … | … | … |

Check log: <date>, contributions <c1,c2,c3>, check value <v>, pairs (1,2) (1,3) (2,3): <r,s> <r,s> <r,s>
Destruction statements: <generation>, <holder>, <date>, <signed statement>
Replacements: <date>, <leaving holder> → <new holder>, <reason>
```
