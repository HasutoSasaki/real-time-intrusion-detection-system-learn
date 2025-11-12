from scapy.all import IP, TCP
from intrusion_detection_system import IntrusionDetectionSystem

def test_ids():
    # 様々なシナリオをシミュレートするためのテストパケットを作成
    test_packets = [
        # 正常なトラフィック
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),

        # SYNフラッド攻撃のシミュレーション
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),

        # ポートスキャンのシミュレーション
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]

    ids = IntrusionDetectionSystem()

    # サンプルの正常トラフィックデータで異常検知器を訓練
    # 実際のシナリオでは、過去の正常トラフィックで訓練される
    import numpy as np
    normal_traffic = np.random.rand(100, 3) * 100  # 100サンプル、3つの特徴量
    ids.detection_engine.train_anomaly_detector(normal_traffic)

    # パケット処理と脅威検知のシミュレーション
    print("Starting IDS Test...")
    for i, packet in enumerate(test_packets, 1):
        print(f"\nProcessing packet {i}: {packet.summary()}")

        # パケットを分析
        features = ids.traffic_analyzer.analyze_packet(packet)

        if features:
            # 特徴量に基づいて脅威を検知
            threats = ids.detection_engine.detect_threats(features)

            if threats:
                print(f"Detected threats: {threats}")
            else:
                print("No threats detected.")
        else:
            print("Packet does not contain IP/TCP layers or is ignored.")

    print("\nIDS Test Completed.")

if __name__ == "__main__":
    test_ids()