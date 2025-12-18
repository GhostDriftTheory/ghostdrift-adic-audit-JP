# Ghost Drift Audit (ADIC) — Scientific Integrity v8.0

LightGBM の予測を **「責任ある道具」**に変換するための、監査（Audit）＋証明書（Certificate）＋台帳（Ledger）生成スクリプトです。  
`commercial / paper / demo` の運用モードを同一コードで切り替えます。

---

## 重要: 同梱CSVはダミー（合成データ）

このリポジトリに置く `electric_load_weather.csv` と `power_usage.csv` は **ダミー（合成データ）**です。  
権利関係が不明な実データ（電力会社・気象機関などの配布物）は同梱しません。

- 目的: スクリプトが **エラーなく起動**し、`adic_out/` に成果物を出力できることの確認
- 実運用・論文用途: **自分が利用権限を持つ実データに置き換えてください**

---

## リポジトリ構成（推奨）

```
.
├─ ghost_drift_audit.py
├─ electric_load_weather.csv
├─ power_usage.csv
└─ adic_out/                    # 実行後に自動生成
```

---

## Quick Start

1) CSV を `.py` と同じフォルダへ配置
- `electric_load_weather.csv`
- `power_usage.csv`

※ もし手元のダミーCSVが `*_dummy.csv` 名なら、以下にリネームしてください
- `electric_load_weather_dummy.csv` → `electric_load_weather.csv`
- `power_usage_dummy.csv` → `power_usage.csv`

2) 実行
```bash
python ghost_drift_audit.py
```

3) 出力（`adic_out/`）を確認
- `certificate.json`
- `ledger.csv`
- `events.csv`
- `evidence_timeseries.csv`
- `business_summary.json`

---

## 入力CSV仕様（Data Contract）

### electric_load_weather.csv

必須列
- `DATETIME` : `YYYY-MM-DD HH:MM:SS`（1時間刻み推奨）
- `TEMP`

`commercial / paper` で追加必須（コード設定により要求）
- `HUMID`
- `SUN`

### power_usage.csv

必須列
- `DATETIME` : `YYYY-MM-DD HH:MM:SS`（1時間刻み）
- `DEMAND` : 数値（負値なし推奨）

注意
- `DATETIME` で weather と demand を突合します。重なりが薄いと停止します。

---

## 実行モード（PROFILE）

スクリプト先頭の `AUDIT_CONFIG['PROFILE']` で切り替えます。

- `commercial`
  - 外部CSV前提・厳格ゲート・証明書に Verdict（OK/NG）を出す
- `paper`
  - 分割ルールを固定して再現性を優先
- `demo`
  - 学習・デモ用途（判定を強く出さない設計）

---

## 出力物の意味

- `certificate.json`
  - 実行条件・入力指紋・主要メトリクス等をまとめた「証明書」
- `ledger.csv`
  - 証明書の要約を追記していく「台帳」
- `events.csv`
  - 監査イベント一覧
- `evidence_timeseries.csv`
  - 予測・残差・スコア・判定など、再検証の最小時系列
- `business_summary.json`
  - 意思決定向けの要約（badge / verdict / next_action 等）

---

## 依存関係

- Python 3.10+ 推奨
- numpy / pandas / matplotlib / lightgbm

```bash
pip install numpy pandas matplotlib lightgbm
```

---

## 「あと一歩」だけ残るとしたら（追加実装なし）

科学者が最後に気にするのは、「これって何を“保証”してて、何を“保証しない”の？」です。  
レポートの完成度を上げるために、以下を **文章で固定**します。

### Scope / Non-claims

**Scope（保証すること）**: 本手法は統計的最適性や真の因果を保証するものではなく、運用における介入判断のために、モデルの振る舞いと前提破綻（入力・分布・運用ルールの破れ）を可観測化し、証拠（証明書・台帳・時系列証拠）として残すことを目的とする。  
**Non-claims（保証しないこと）**: 本手法は将来の誤差ゼロ、最良モデルの自動選択、外挿領域での一般化、全ての不正の完全検出を保証しない。スコアや閾値は運用設計であり、数学的に唯一の正解であることは主張しない。

### Threat model（3行）

- budget（予算制約）を口実に閾値を上げ、異常を見えなくする
- rolling（基準更新）を都合よく動かし、比較基準そのものを改変する
- 入力CSVの差し替え・欠損埋めの恣意・時刻ずらしで監査をすり抜ける

上の脅威に対して、**cap（上限制約） / fingerprints（入力・設定の指紋） / suppressed（抑制・除外の記録）** を出力し、後から改変の余地が残りにくい形で「運用の証拠」を固定します。

### スコア定義について

スコア定義はヒューリスティックです。たとえば `SCORE = max(S_RES, S_GRAD)` のように「大きい方を採用」するのは、見逃しを減らすための **保守的な設計判断**です。これは理論保証ではなく設計上の選択であるため、その旨をレポートに明記します。

---

## License

- コードのライセンスは `LICENSE` に従います。
- CSV は合成データです（特定組織の実データではありません）。

---

## 1行まとめ

**「予測」ではなく「予測に責任を持つ」ための ADIC 監査＋証明書＋台帳の最小実装。**
