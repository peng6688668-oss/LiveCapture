# LiveCapture — Projekt-Regeln

## Antwort-Abschluss: Fuenf Folgevorschlaege — WICHTIG
Jede Antwort **MUSS** am Ende mit **fuenf konkreten Folgevorschlaegen** abschliessen.
Zweck: Dem Nutzer weiterfuehrende Ideen geben, blinde Flecken aufdecken,
und den Arbeitsfluss am Laufen halten — aehnlich wie Gemini "Suggested Actions".

Regeln:
- Vorschlaege muessen **kontextbezogen** sein (zum gerade bearbeiteten Thema passen)
- Koennen sein: verwandte Optimierungen, moegliche Probleme, naechste logische Schritte,
  alternative Ansaetze, Tests, UI-Verbesserungen
- Kurz und konkret formuliert (je 1–2 Saetze)
- Format: als Frage oder Vorschlag am Ende der Antwort

---

## Auto-Commit & Push — WICHTIG

Nach jeder Code-Aenderung in diesem Projekt **MUSS** automatisch:
1. `git add` der geaenderten Dateien
2. `git commit` mit aussagekraeftiger Commit-Message (conventional commits Format)
3. `git push github master` zum Remote `github` (github.com/peng6688668-oss/LiveCapture)

Dies gilt fuer JEDE Aenderung — egal ob Bug-Fix, neues Feature oder Refactoring.
Nicht warten bis der Nutzer darum bittet.

---

## PLP / TECMP / CMP — Protokoll-Kurzreferenz

| Protokoll | EtherType | Quelle | Version-Byte |
|-----------|-----------|--------|--------------|
| **PLP** | `0x2090` | ViGEM Vehicle Data Logger | byte[4] |
| **TECMP** | `0x99FE` | Technica Capture Module | byte[4] = 2 oder 3 |
| **ASAM CMP** | `0x99FE` | ASAM Standard | byte[0] = 0x01 |

- PLP und TECMP verwenden das gleiche Header-Format (28 Bytes)
- ASAM CMP hat ein anderes Header-Format (8 Bytes) — gleicher EtherType
- Info-Spalte zeigt Quelle: `PLP CAN 2.0`, `TECMP CAN FD`, `PCAN CAN`
- Vollstaendige Referenz: `~/.claude/projects/-home-pengzhang/memory/plp_tecmp_cmp_protocols.md`
