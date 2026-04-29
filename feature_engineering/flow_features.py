class FlowFeatures:

    def safe(self, value):
        """Convert safely to int"""
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return value
        try:
            return int(value)
        except:
            return 0

    def extract(self, flow_data):

        if not isinstance(flow_data, dict):
            return {
                "packet_count": 0,
                "protocol": 0,
                "src_port": 0,
                "dst_port": 0
            }

        return {
            "packet_count": self.safe(flow_data.get("packet_count")),
            "protocol": self.safe(flow_data.get("protocol")),
            "src_port": self.safe(flow_data.get("src_port")),
            "dst_port": self.safe(flow_data.get("dst_port"))
        }