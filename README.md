🌀 Ghost Drift Audit (ADIC)

Framework for Predictive Accountability & Mathematical Integrity

ghost-drift-audit-jp は、機械学習モデル（LightGBM等）の予測プロセスに対し、**数学的説明責任（Mathematical Accountability）**を付与するための監査エンジンです。ADIC (Analytically Derived Interval Computation) 理論の実装により、AIをブラックボックスから「検証可能な責任ある道具」へと再定義します。

💎 Design Philosophy: From "Probabilistic" to "Accountable"

従来のAI運用が抱える「不透明な推論」という課題に対し、本フレームワークは以下の3点を保証します。

Audit-First Design: 予測実行と同時に、第三者が検証可能な「証拠（Evidence）」を自動生成。

Immutable Fingerprints: 入力データと設定パラメータのハッシュ指紋を固定し、後付けの改ざんを抑止。

Verifiable Integrity: 統計的な最適性ではなく、運用ルールに対する「誠実な振る舞い」を可視化。

🛠 Technical Specifications

System Requirements

Language: Python 3.10 or higher

Core Dependencies: numpy, pandas, matplotlib, lightgbm

Project Structure

.
├── ghost_drift_audit.py      # Core Logic & ADIC Audit Engine
├── electric_load_weather.csv  # Input: Weather Time-series (Synthetic)
├── power_usage.csv            # Input: Demand Time-series (Synthetic)
└── adic_out/                  # Output: Compliance Artifacts & Ledger


Execution Profiles (AUDIT_CONFIG['PROFILE'])

運用フェーズに合わせ、監査の厳格性を以下の3モードから選択可能です。

Profile

Target Audience

Integrity Level

Features

commercial

Enterprise Ops

High

厳格なゲート判定、意思決定用Verdict（OK/NG）の自動生成。

paper

Researchers

Rigid

分割ルールの固定による100%の計算再現性の担保。

demo

Developers

Flexible

フレームワークの挙動理解を優先した緩和モード。

🚀 Deployment & Usage

1. Setup Environment

pip install numpy pandas matplotlib lightgbm


2. Prepare Data

.py と同じディレクトリに以下のCSVを配置してください。

[!CAUTION]
同梱のCSVは合成データ（Dummy）です。
スクリプトの正常動作確認用であり、実運用・研究用途では自身が権利を持つ実データに置き換えてください。

3. Run Audit Engine

python ghost_drift_audit.py


4. Verification of Artifacts (adic_out/)

実行後、以下のコンプライアンス成果物が生成されます。

📜 certificate.json: 実行コンテキスト、データ指紋、判定サマリーを網羅した「証明書」。

📑 ledger.csv: すべての予測と判定の履歴を蓄積する「台帳」。

📉 evidence_timeseries.csv: 再検証（Re-verification）を可能にする最小粒度の時系列証拠。

⚖️ Scope & Integrity (Safety Non-claims)

🎯 Scope & Non-claims

Scope（保証すること）: モデルの振る舞いと前提破綻（入力・分布の破れ）を可観測化し、運用上の介入判断のための証跡を固定すること。

Non-claims（保証しないこと）: 将来の誤差ゼロ、数学的な「唯一の正解」の提示、外挿領域での一般化を保証するものではありません。

🛡️ Threat Model

ADICは以下の「運用の不誠実さ」に対する防御（記録）を提供します。

閾値操作: 異常を隠蔽するための恣意的な閾値変更 → Cap（制約）の記録

基準改変: 比較基準（Rolling Window等）の改変 → 設定指紋の固定

データ捏造: 入力CSVの差し替えや時刻ずらし → Data Fingerprints による照合

📜 License

Code: MIT License

Data: Synthetic dataset for demonstration purposes.

「予測」を「責任」へ。
Produced by GhostDrift Mathematical Institute (GMI)
Official Website
