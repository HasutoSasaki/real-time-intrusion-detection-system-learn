from collections import defaultdict
from scapy.all import IP, TCP

# ネットワークトラフィックを分析するクラス
# キャプチャされたパケットを処理し、関連する特徴を抽出します
# 接続フローを追跡し、パケットの統計情報をリアルタイムで計算
class TrafficAnalyzer:
    def __init__(self):
        # defaultdict のデータ構造を使用して、フローごとにデータを整理し、接続とフロー統計情報を管理.
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None, # 開始時間
            'last_time': None # 最新パケット時間
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src # IPアドレス抽出
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport # ポート番号抽出
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    # フローと現在のパケットの詳細な特性を計算します。
    # ネットワークトラフィックパターン、異常、または潜在的な脅威を特定するのに非常に役立ちます。
    def extract_features(self, packet, stats):
        # 時間差を計算(ゼロ除算を避けるため、最小値を設定)
        time_diff = max(stats['last_time'] - stats['start_time'], 0.0001)

        return {
            'packet_size': len(packet),
            'flow_duration': stats['last_time'] - stats['start_time'], # フロー期間
            'packet_rate': stats['packet_count'] / time_diff, # パケット送信レート:単位時間あたりに送信されるパケット数
            'byte_rate': stats['byte_count'] / time_diff, # データ転送レート:単位時間あたりに転送されるデータ量（スループット）
            'tcp_flags': packet[TCP].flags, # TCPフラグのビットマスク:TCP接続の状態を示すフラグ（SYN, ACK, FIN, RST, PSH, URGなど）
            'window_size': packet[TCP].window # TCP受信ウィンドウサイズ（バイト）: 受信側が一度に受け取れるデータ量
        }