class FlowFeatures:

    def extract(self, flow_data):

        return {
            "packet_count": flow_data.get("packet_count", 0),
            "protocol": flow_data.get("protocol"),
            "src_port": flow_data.get("src_port"),
            "dst_port": flow_data.get("dst_port")
        }