# Plan d'implémentation : tests `internal/dashboard`

## Quality bar

Ce plan vise un niveau **enterprise / open source tier / production ready**, dans la continuité de `STORAGE_TESTS_PLAN.md` :

- Tests qui **valident un contrat HTTP**, pas le moteur `html/template` (qui est testé par la stdlib Go).
- Tests **déterministes** : aucun port hardcodé (utiliser `httptest.Server` qui pick un port libre), aucun `time.Sleep` aveugle pour les tests de lifecycle.
- Tests **isolés** : un store en mémoire fake par test, jamais de partage.
- Tests qui passent **avec `-race`** et **`-shuffle=on`**.
- Couverture **du contrat externe** (chemins HTTP visibles aux clients) prioritaire sur la couverture de lignes internes.

## État actuel

| Fichier | LOC | Coverage |
|---|---|---|
| `server.go` | 242 (dont ~100 de template HTML/JS) | **0%** |

**Objectif réaliste** : passer de 0% → **90-95%**. Le template HTML inline et `ListenAndServe` (boucle serveur) sont les seules zones non triviales à couvrir.

## Stratégie globale

Le dashboard est **un petit serveur HTTP avec 3 routes** :
- `GET /` → page HTML statique (template Go)
- `GET /api/entries?...` → JSON d'audit entries filtrées
- `GET /api/stats` → JSON d'aggregate stats

**Aucune dépendance externe** : tout passe par `audit.Store` injecté. On peut donc :
- Tester chaque handler via `httptest.NewRecorder()` directement (rapide, sans bind de port)
- Tester `ListenAndServe` une seule fois avec `httptest.NewServer` ou via un context cancel (pattern déjà utilisé dans `metrics/recorder_test.go`)
- Réutiliser le pattern `fakeStore` qu'on a écrit pour `internal/audit/logger_test.go` — ou exporter ce fake si pertinent (à éviter, juste copier-coller : 20 lignes)

**Pas de mocks pour `audit.Store`** : un in-memory store qui implémente l'interface (4 méthodes) est plus lisible.

---

## Plan détaillé

### 1. `server_test.go` (un seul fichier, ~250 lignes)

- **Cible** : 0% → 95%+
- **Effort** : ~250 lignes de test
- **Fixture** : `audit.Store` fake en mémoire + `httptest.NewRecorder()` + 1 test `ListenAndServe` lifecycle

#### Handler `GET /` (index)

- `TestServerIndexRendersHTML` — GET `/`, vérifier status 200, content-type `text/html; charset=utf-8`, body contient un marker du template (genre `<title>` ou `<table>`). **Ne pas asserter le HTML complet** — c'est de la doc, pas du contrat.
- `TestServerIndexResponseIsCacheable` — pas requis pour l'instant, à oublier (pas de cache header dans le code aujourd'hui).

#### Handler `GET /api/entries`

- `TestServerEntriesReturnsAllWhenNoFilter` — store contient 3 entries, GET `/api/entries`, vérifier JSON array de 3 éléments.
- `TestServerEntriesAppliesMethodFilter` — store contient 3 ping + 2 tools/call, GET `/api/entries?method=ping`, vérifier 3 entries renvoyées.
- `TestServerEntriesAppliesToolNameFilter` — idem pour `?tool_name=read_file`.
- `TestServerEntriesAppliesClientIDFilter` — idem pour `?client_id=claude`.
- `TestServerEntriesAppliesTimeRangeFilter` — `?from=...&to=...` avec timestamps RFC3339, vérifier filtrage correct.
- `TestServerEntriesAppliesLimit` — store contient 10 entries, GET `/api/entries?limit=3`, vérifier 3 entries.
- `TestServerEntriesDefaultLimitIs100` — store contient 150 entries, GET `/api/entries`, vérifier 100 entries (default `limit=100`).
- `TestServerEntriesRejectsInvalidLimit` — GET `/api/entries?limit=abc`, vérifier status 400.
- `TestServerEntriesRejectsInvalidFromTimestamp` — GET `/api/entries?from=not-a-date`, vérifier 400.
- `TestServerEntriesRejectsInvalidToTimestamp` — idem pour `to`.
- `TestServerEntriesReturns500OnStoreError` — fakeStore configuré pour retourner erreur sur Query, vérifier 500.
- `TestServerEntriesReturnsValidJSON` — décoder la réponse en `[]audit.Entry`, vérifier round-trip propre.

#### Handler `GET /api/stats`

- `TestServerStatsReturnsAggregates` — store avec entries variées, GET `/api/stats`, vérifier JSON contient `total_today`, `error_rate`, `top_tools`.
- `TestServerStatsReturns500OnStoreError` — fakeStore qui retourne err sur Stats(), vérifier 500.
- `TestServerStatsReturnsValidJSON` — décoder en `audit.Stats`, vérifier round-trip.

#### `queryFilter` (helper)

Indirectement testé par les tests `entries`, mais 2-3 tests directs ajoutent de la précision :

- `TestQueryFilterEmptyDefaultsToLimit100` — `r.URL.Query()` vide, vérifier `Limit == 100` et tous les autres champs à zero value.
- `TestQueryFilterParsesAllFields` — URL avec method+tool_name+client_id+from+to+limit, vérifier tous les champs peuplés.
- `TestQueryFilterRejectsNonRFC3339Timestamps` — `?from=2026-01-01` (sans timezone), vérifier erreur.

#### `ListenAndServe` (lifecycle)

- `TestServerListenAndServeShutdownsOnContextCancel` — démarre, attend que le port soit accessible, cancel context, vérifier retour clean en <3s. Pattern identique à `metrics/recorder_test.go:TestPrometheusRecorderListenAndServeShutdownsOnContextCancel`.
- `TestServerListenAndServeReturnsNilWhenDisabled` — Config.Enabled = false, ListenAndServe ne démarre rien et retourne nil immédiatement.
- `TestServerListenAndServeReturnsErrorOnBindFailure` — bind un port d'abord via `net.Listen("0.0.0.0:0")`, démarrer le dashboard sur ce port, vérifier erreur de bind (pattern identique à `TestPrometheusRecorderListenAndServeReturnsErrorOnBindFailure`).

#### `NewServer` (constructor)

- `TestNewServerNilLogFallsBackToDefault` — Config sans Log, NewServer ne panique pas, un GET ne panique pas non plus.

---

## Estimation

| Section | Tests | Lignes |
|---|---|---|
| Handler `/` (index) | 1 | ~20 |
| Handler `/api/entries` | 12 | ~120 |
| Handler `/api/stats` | 3 | ~30 |
| `queryFilter` direct | 3 | ~30 |
| `ListenAndServe` lifecycle | 3 | ~50 |
| `NewServer` | 1 | ~10 |
| Fake store + helpers | — | ~30 |
| **Total** | **23 tests** | **~290 lignes** |

## Impact sur coverage globale

- Le package `dashboard` contient ~242 LOC.
- Le passer à 95% ajoute environ **+3 à 4 points de coverage globale** (de 63.3% → ~67%).

C'est un gain modeste en pourcentage global, mais l'API du dashboard est **publique** (consommée par des scripts d'audit externes potentiellement). Un test robuste du contrat HTTP a plus de valeur qu'un test interne d'un helper.

## Ordre d'implémentation recommandé

1. **Fake store + helpers** d'abord — fondation des tests
2. **Handlers `entries` et `stats`** — le contrat API, la majorité de la valeur
3. **`queryFilter` direct** — quelques edge cases que les handlers couvrent moins finement
4. **`ListenAndServe` lifecycle** — le pattern existe déjà dans `metrics/recorder_test.go`, copier-adapter
5. **Index handler** + `NewServer` — quick wins

---

## Best practices spécifiques au testing HTTP

### Pattern recommandé : `httptest.NewRecorder` plutôt que `httptest.NewServer`

Pour 90% des tests, le pattern suivant est plus rapide et plus déterministe :

```go
func TestServerEntriesAppliesMethodFilter(t *testing.T) {
    store := &fakeStore{entries: []audit.Entry{
        {Method: "ping"},
        {Method: "ping"},
        {Method: "tools/call"},
    }}
    server := NewServer(Config{Store: store})

    req := httptest.NewRequest(http.MethodGet, "/api/entries?method=ping", nil)
    rec := httptest.NewRecorder()
    server.entries(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("status = %d, want 200", rec.Code)
    }
    var entries []audit.Entry
    if err := json.NewDecoder(rec.Body).Decode(&entries); err != nil {
        t.Fatalf("decode: %v", err)
    }
    if len(entries) != 2 {
        t.Fatalf("entries = %d, want 2", len(entries))
    }
}
```

**Avantages** :
- Pas de port à allouer
- Pas de bind/listen
- Synchrone, pas de goroutine à attendre
- 100% déterministe

**Limite** : on appelle les handlers directement (`server.entries`), donc on ne teste pas le routing (`mux.HandleFunc`). Pour ça, un seul test via `httptest.NewServer` qui tape `/api/entries` via HTTP réel suffit (3 lignes pour vérifier que les 3 routes existent).

### Fake store recommandé

```go
type fakeStore struct {
    entries  []audit.Entry
    stats    audit.Stats
    queryErr error
    statsErr error
}

func (s *fakeStore) Append(audit.Entry) error             { return nil }
func (s *fakeStore) Query(audit.QueryFilter) ([]audit.Entry, error) {
    if s.queryErr != nil { return nil, s.queryErr }
    return s.entries, nil
}
func (s *fakeStore) Stats() (audit.Stats, error) {
    if s.statsErr != nil { return audit.Stats{}, s.statsErr }
    return s.stats, nil
}
func (s *fakeStore) Close() error { return nil }
```

Note : on **ne réimplémente pas la logique de filter** dans le fakeStore. Les tests passent un store qui contient déjà les bonnes entries pour le cas, ou on utilise le vrai filtrage si on veut tester la chaîne complète (mais alors c'est un test d'intégration, pas un test unitaire du handler).

### Anti-patterns à éviter ici

- ❌ **Tester le HTML du template** — caractères, classes CSS, structure DOM. C'est de la doc, ça change tout le temps, ça pollue.
- ❌ **Goldenfile pour le template** — même problème, et les goldenfiles encouragent l'acceptance sans relecture critique.
- ❌ **`go test -tags=integration` pour ce package** — tout est testable en unit, pas besoin de séparation.
- ❌ **`time.Sleep` pour attendre que le serveur démarre** dans le test `ListenAndServe`. Utiliser le polling avec timeout court (déjà fait dans `metrics/recorder_test.go`).
- ❌ **Hardcoder un port** dans les tests `ListenAndServe`. Utiliser `net.Listen("0.0.0.0:0")` puis lire le port effectif via `.Addr().(*net.TCPAddr).Port`.

### Ce qui sera **NON** couvert

Identifier les zones qu'on **ne teste pas** est aussi important que ce qu'on teste :

- **Le HTML/JS du template** (~100 lignes) : on vérifie qu'il rend (status 200, content-type, présence d'un marker), pas son contenu. Le moteur `html/template` est testé par Go.
- **`writeJSON` chemin d'erreur** : `json.Encoder.Encode` ne peut échouer que si la struct contient un type non-encodable. `audit.Entry` et `audit.Stats` n'en contiennent pas. Inatteignable sans modifier le code de production.
- **`s.server.Shutdown` returning error** : nécessite de mocker `http.Server`. Pas de valeur, pas testé.

Ces ~5% restants resteront non couverts et c'est **OK** — on tend vers 95%, pas vers 100%.

---

## Prochaines cibles après dashboard

Une fois ce plan exécuté, l'état projeté serait :

| Package | Avant | Après dashboard | Gain |
|---|---|---|---|
| `internal/dashboard` | 0% | 95% | +95 |
| **Total projet** | 63.3% | **~67%** | **+3.7** |

Pour aller au-delà de 67% :

- **`internal/proxy` (45%)** : c'est le gros morceau restant (~1300 LOC). Les zones non couvertes (`ListenAndServe`, `streamSSE`, `pipeClientToServer/ServerToClient`, `Run` stdio) sont **très** difficiles à tester. Plan séparé nécessaire, plus complexe.
- **`cmd/mcp-audit` (39%)** : `loadConfig`/`validateConfig` sont déjà couverts. Le reste = `main()`, signal handling, store creation, proxy lifecycle. Pas le bon investissement.
- **`internal/otel` (79% → 90%+)** : les trous restants sont des chemins d'erreur HTTP. Petit gain, peu de valeur.

Mon avis : **après dashboard, s'arrêter à ~67% est sain** pour aller vers 1.0.0. Les ~13 points restants seraient gagnés sur du code I/O complexe qui mérite plutôt des **tests d'intégration end-to-end** (le E2E manuel que tu as déjà fait sur 0.6.1) qu'une chasse aux pourcentages.

---

## Risques / vigilances spécifiques au dashboard

- **Le template est inline dans le code** (`var pageTemplate = template.Must(...)`). Si quelqu'un casse la syntaxe du template, le package ne compile plus du tout (panic au load). Pas besoin d'un test pour ça, le `go build` l'attrape.
- **`audit.QueryFilter.Limit` default = 100** est implémenté côté `queryFilter` du dashboard, mais aussi côté `audit.LimitNewest` qui défaultise à 100 si `limit <= 0`. Les deux defaults se cumulent. Tester explicitement qu'un `?limit=0` ne donne **pas** 0 entries (ce serait un bug user).
- **`from`/`to` parsing en RFC3339 strict** : `2026-01-01` (sans timezone) sera rejeté. C'est intentionnel mais surprenant. Tester pour verrouiller le comportement.
- **Concurrence Store** : le dashboard appelle `store.Query` et `store.Stats` en concurrence avec les writes du proxy. La sécurité de cette concurrence est la responsabilité du `Store` (testée dans `storage_test.go`), pas du dashboard.
