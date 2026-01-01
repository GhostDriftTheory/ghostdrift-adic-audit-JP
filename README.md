**再現可能なドリフト検知のための証明書監査：時系列予測の実証**

<div align="center">
</div>

ghost-drift-audit-jp は、運用中の時系列予測におけるドリフト（分布変化／regime shift）の判定を、**追試可能なプロトコル**として固定するための監査エンジンです。分割境界（split）、閾値ポリシー（thresholds）、入力データ同定、実行コード、実行環境を証明書（certificate）として一体化して出力し、第三者が同一入力から同一の監査結論（OK/NG）を再生成できる形にします。特に、推定は Calibration 期に限定し、Test 期は評価のみに用いることで、結果を見た後の閾値調整（後付け最適化）を構造的に排除します。ケーススタディとして、電力需要×気象の時系列データ（2024年1–4月）を対象に、証明書・台帳・エビデンス時系列を生成し、監査結論を再現可能なアーティファクトとして提示します。

## 🔗 Quick Links

* 📂 **Source Code:** [GitHub Repository](https://github.com/GhostDriftTheory/ghostdrift-adic-audit-JP)
* 📜 **Main Script:** [ghost_drift_audit_JP.py](https://github.com/GhostDriftTheory/ghostdrift-adic-audit-JP/blob/main/ghost_drift_audit_JP.py)
* 📦 **Download:** [Project ZIP](https://github.com/GhostDriftTheory/ghostdrift-adic-audit-JP/archive/refs/heads/main.zip)
* 📖 **Documentation:** [Online Manual](https://ghostdrifttheory.github.io/ghostdrift-adic-audit-JP/)（[⚙️ 実行モードへ直行](https://ghostdrifttheory.github.io/ghostdrift-adic-audit-JP/#profile)）
* 🚨 **Support:** [Report Issues](https://github.com/GhostDriftTheory/ghostdrift-adic-audit-JP/issues)

---

## 📑 Audit Report (PDF)

- **Report:** [Scientific Audit Report on Structural Integrity of Forecasting Models (JP)](./Scientific%20Audit%20Report%20on%20Structural%20Integrity%20of%20Forecasting%20Models_JP.pdf)
- **Verdict:** NG (TAU_CAP_HIT)
- **Protocol:** Ghost Drift Audit v8.0

---

## 💎 Design Philosophy: From "Probabilistic" to "Accountable"

従来のAI運用が抱える「不透明な推論」という課題に対し、本フレームワークは以下を提供します。

> [!TIP]
> **Audit-First Design**
> 予測実行と同時に、第三者が客観的に検証可能な「証拠（Evidence）」を自動生成します。

> [!IMPORTANT]
> **Tamper-evident Fingerprints**
> 入力データと設定パラメータのハッシュ指紋を固定。後付けの改変を数学的に検知可能にします。

> [!NOTE]
> **Verifiable Integrity**
> 単なる統計的最適性ではなく、運用ルールに対する「誠実な振る舞い」を可視化します。

---

## 🛠 Technical Specifications

### System Requirements

* **Language:** Python 3.10+
* **Dependencies:** numpy, pandas, matplotlib, lightgbm

### Project Structure

```text
.
├── ghost_drift_audit_JP.py    # Core Logic & Audit Engine
├── electric_load_weather.csv  # Input: Weather (Synthetic)
├── power_usage.csv            # Input: Demand (Synthetic)
└── adic_out/                  # Output: Accountability Ledger
```

---

<a id="profile"></a>

## ⚙️ 実行モード (Execution Profiles)

AUDIT_CONFIG['PROFILE'] で監査の厳格性を切り替えます。

| Profile    | 用途 / ターゲット |  厳格さ | 主な特徴                |
| ---------- | ---------- | ---: | ------------------- |
| demo       | 動作確認 / 学習  |  Low | 挙動理解と証拠出力を優先        |
| paper      | 研究 / 再現実験  |  Mid | seed固定による計算再現性を担保   |
| commercial | 実運用 / 意思決定 | High | 厳格なゲート判定とVerdictを生成 |

### 設定方法

```python
AUDIT_CONFIG = {
  "PROFILE": "demo",  # "demo" | "paper" | "commercial"
}
```

---

## 🚀 Deployment & Usage

### 1. Setup

```bash
pip install numpy pandas matplotlib lightgbm
```

### 2. Prepare Data

.py と同じディレクトリにCSVを配置してください。

> [!CAUTION]
> 同梱のCSVは合成データ（Dummy）です。
> 動作確認用であり、実運用や研究には自身が権利を持つ実データを使用してください。

### 3. Run

```bash
python ghost_drift_audit_JP.py
```

### 4. Verification (adic_out/)

* 📜 **certificate.json:** 実行条件と判定サマリーの「証明書」
* 📑 **ledger.csv:** すべての履歴を記録する不変の「台帳」
* 📉 **evidence_timeseries.csv:** 再検証用の時系列エビデンス

---

## ⚖️ Scope & Integrity (Non-claims)

### 🎯 Scope & Limits

* **Scope:** モデルの振る舞いと前提破綻を可観測化し、介入判断のための証跡を固定すること。
* **Non-claims:** 将来の誤差ゼロ、数学的な「唯一の正解」、外挿領域での一般化は保証しません。

### 🛡️ Threat Model (改変検知)

* **閾値操作:** 異常隠蔽のための恣意的な変更 → Cap記録により検知
* **基準改変:** 比較基準の事後変更 → 設定指紋の不一致で検知
* **データ捏造:** 入力の差し替えや捏造 → Data Fingerprints で照合

---

## 📜 License & Acknowledgments

* **Code:** MIT License
* **Data:** Synthetic dataset for demonstration.

Patent Notice: This repository implements techniques related to a pending patent application. Japanese Patent Application No. 特願2025-182213. This notice does not restrict use of the open-source code under the MIT License.

**「予測」を「責任」へ。**
Produced by **GhostDrift Mathematical Institute (GMI)** — [Official Website](https://www.ghostdriftresearch.com/) | [Online Documentation](https://ghostdrifttheory.github.io/ghostdrift-adic-audit-JP/)
