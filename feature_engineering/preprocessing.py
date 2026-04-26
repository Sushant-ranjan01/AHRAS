class Preprocessor:

    def normalize(self, features):

        return {
            "packet_count": min(features.get("packet_count", 0) / 100, 1),
            "protocol": features.get("protocol", 0) / 255,
            "src_port": features.get("src_port", 0) / 65535,
            "dst_port": features.get("dst_port", 0) / 65535
        }