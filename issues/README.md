# Issues — Problemarchiv & Erfahrungsdatenbank

Dieses Verzeichnis sammelt **Analysen, Root Causes und Loesungen** fuer
aufgetretene Probleme. Ziel: Erfahrungen fixieren, Debugging beschleunigen,
gleiche Fehler nicht zweimal machen.

## Namenskonvention

`<Kurzname>.md` — z.B. `RCCB_rosa_vorhang.md`, `PLP_counter_reset.md`

## Datei-Struktur (Vorlage)

```markdown
# <Titel>

> Erstellt: YYYY-MM-DD
> Status: OFFEN | IN ARBEIT | GELOEST
> Geloest: YYYY-MM-DD (falls geloest)

## Symptom
Was sieht man? Wie reproduziert man es?

## Ursache
Root Cause Analyse.

## Loesung
Was wurde gemacht? Welche Dateien/Zeilen betroffen?

## Erkenntnisse
Was hat man gelernt? Worauf in Zukunft achten?
```

## Index

| Datei | Status | Kurzbeschreibung |
|-------|--------|-----------------|
| `RCCB_rosa_vorhang.md` | OFFEN | RCCB Clear-Kanal Crosstalk → beige Vorhaenge erscheinen rosa |
| `PLP_paketverlust_CCA_pfad.md` | GELOEST | CCA 9010 veraendert Paket-Timing → NIC Adaptive Coalescing → rx_missed |
