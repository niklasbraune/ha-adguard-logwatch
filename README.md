# AdGuard Log Watch

Home-Assistant-Add-on zur regelbasierten Auswertung des AdGuard-Home-Query-Logs. Es stellt eine Weboberflaeche auf Port `8099` bereit, prueft das Log in einem einstellbaren Intervall und versendet bei Schwellwerttreffern Pushover-Benachrichtigungen.

## Installation

1. Dieses Repository als lokales Add-on-Repository in Home Assistant hinzufuegen oder den Ordner nach `addons/adguard_logwatch` kopieren.
2. Add-on installieren und starten.
3. Die Oberflaeche unter `http://<home-assistant-host>:8099` oeffnen.
4. AdGuard-URL, Zugangsdaten und optional Pushover-Zugangsdaten hinterlegen.
5. Regeln anlegen und mit **Jetzt auswerten** testen.

## Regeln

Eine Regel verbindet Suchmuster, Vergleichsart, optionale Clients, DNS-Status, Mindesttreffer und Zeitfenster. Bei einem Treffer wird das Home-Assistant-Event `adguard_logwatch_match` mit `rule`, `rule_id`, `count` und `threshold` versendet. Die Ruhezeit verhindert wiederholte Pushover-Meldungen.

Die Konfiguration wird unter `/data/logwatch.json` gespeichert. Secrets werden im Browser nach dem Speichern maskiert und nicht ueber die Konfigurations-API ausgegeben.

## Hinweise

- Die AdGuard-URL muss den Port der AdGuard-Home-Weboberflaeche enthalten, beispielsweise `http://192.168.1.2:3000`.
- Das Add-on nutzt `GET /control/querylog?limit=500` mit HTTP Basic Authentication.
- Bei HTTPS sollte ein gueltiges Zertifikat verwendet werden. Selbstsignierte Zertifikate werden absichtlich nicht akzeptiert.