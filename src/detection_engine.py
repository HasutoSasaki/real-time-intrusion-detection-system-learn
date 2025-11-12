from sklearn.ensemble import IsolationForest
import numpy as np

# シグネチャベースと異常ベースの検知手法を組み合わせたハイブリッドシステム
# 異常検知には Isolation Forest モデルを使用し、特定の攻撃パターンを識別するための事前定義されたルールを使用
# 詳しくはこちら https://medium.com/@corymaklin/isolation-forest-799fceacdda4
class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1, # 全体の10%が異常データだと想定
            random_state=42 # 再現性のための乱数シード固定
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []

    # 既知の攻撃パターンを事前定義したルールで検出する手法
    def load_signature_rules(self):
        return {
            # SYN Floodは最初のSYNだけを大量に送り、ACKを返さないことでサーバーのリソースを消費させる。
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and  # SYN flag
                    features['packet_rate'] > 100
                )
            },
            # ポートスキャンとは： 攻撃者がターゲットサーバーの開いているポートを調べる行為
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                )
            }
        }

    # 通常の交通特性データセットを用いて Isolation Forest モデルを学習
    # これにより、モデルは典型的な交通パターンと異常を区別できるようになります
    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        # 定義済みの各ルールを繰り返し処理し、ルールの条件をトラフィックの特徴に適用します。
        # ルールが一致した場合、シグネチャベースの脅威が確実に記録されます
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection
        # 特徴ベクトル（パケットサイズ、パケットレート、バイトレート）を分離フォレストモデルで処理し、異常スコアを計算します
        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])

        # スコアが異常な動作を示している場合、検出エンジンはそれを異常としてトリガーし、異常の重大度に比例した信頼度スコアを生成します
        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        if anomaly_score < -0.5:  # Threshold for anomaly detection
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats