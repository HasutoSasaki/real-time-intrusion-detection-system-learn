from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue() # キャプチャしたパケットを保存
        self.stop_capture = threading.Event() # パケットキャプチャの停止タイミングを制御するスレッドイベント

    def packet_callback(self, packet):
        # パケットにIP層とTCP層の両方が含まれているかどうかを確認。含まれていたらキューに追加
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    # 指定されたインターフェースでパケットのキャプチャを開始
    def start_capture(self, interface="eth0"): # デフォルトでは eth0 イーサネットインターフェース
        # sniff を実行するための別スレッドを生成
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set()) # イベントがトリガーされた時にキャプチャを停止することを保証

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    # イベントを設定しキャプチャを停止
    # スレッドの実行が完了するまで待機することで、プロセスが確実に終了するようにします。
    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()