class Preprocessor:

    def safe(self, value):
        """Ensure numeric safe value"""
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return value
        try:
            return float(value)
        except:
            return 0

    def normalize(self, features):

        packet_count = self.safe(features.get("packet_count"))
        protocol = self.safe(features.get("protocol"))
        src_port = self.safe(features.get("src_port"))
        dst_port = self.safe(features.get("dst_port"))

        return {
            "packet_count": min(packet_count / 100, 1),
            "protocol": protocol / 255,
            "src_port": src_port / 65535,
            "dst_port": dst_port / 65535
        }