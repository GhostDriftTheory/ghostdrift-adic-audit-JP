🌀 Ghost Drift Audit (ADIC)

Framework for Predictive Accountability & Mathematical Integrity

ghost-drift-audit-jp は、機械学習モデル（LightGBM等）の予測プロセスに対し、**数学的説明責任（Mathematical Accountability）**を付与するための監査エンジンです。ADIC (Analytically Derived Interval Computation) 理論の実装により、AIをブラックボックスから「検証可能な責任ある道具」へと再定義します。

💎 Design Philosophy: From "Probabilistic" to "Accountable"

従来のAI運用が抱える「不透明な推論」という課題に対し、本フレームワークは以下を提供します。

Audit-First Design: 予測実行と同時に、第三者が検証可能な「証拠（Evidence）」を自動生成。

Tamper-evident Fingerprints: 入力データと設定パラメータのハッシュ指紋を固定し、後付けの改変を検知可能にする。

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


<a id="profile"></a>

実行モード（Execution Profiles）: AUDIT_CONFIG['PROFILE']

運用フェーズに合わせ、監査の厳格性を3モードから選択可能です（同一コードで切替）。

Profile

想定読者 / 用途

厳格さ

何が変わるか

demo

学習・動作確認

Low

判定を強く出さず、挙動理解と証拠出力を優先

paper

研究・再現実験

Mid

分割・seed等を固定し、計算再現性を最優先

commercial

実運用・意思決定支援

High

厳格ゲート + Verdict（OK/NG）を自動生成

# 設定例
AUDIT_CONFIG = {
  "PROFILE": "demo",  # "demo" | "paper" | "commercial"
}


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

ADICは以下の「運用の不誠実さ」に対し、改変が起きた事実を検知できる形で記録します。

閾値操作: 異常を隠蔽するための恣意的な閾値変更 → Cap（制約）の記録

基準改変: 比較基準（Rolling Window等）の改変 → 設定指紋の固定

データ捏造: 入力CSVの差し替えや時刻ずらし → Data Fingerprints による照合

📜 License

Code: MIT License

Data: Synthetic dataset for demonstration purposes.

「予測」を「責任」へ。
Produced by GhostDrift Mathematical Institute (GMI)
Official Website | Online Documentation
