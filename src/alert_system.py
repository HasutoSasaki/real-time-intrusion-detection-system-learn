import logging
import json
from datetime import datetime

# 警報システム
# 検出された脅威を構造的に処理し、ログに記録します。また、slack, Jiraチケットなどの追加の通知メカニズムを追加しても拡張できます
class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        # 検出された脅威の信頼度レベルが高い場合(0.8を超える場合)、アラートはエスカレーションされ、CRITICAL レベルメッセージになります
        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
            # Implement additional notification methods here
            # (e.g., email, Slack, SIEM integration)