protocol_feature_dict = {
    # "common": ["number", "response_number", "ip1", "ip2", "port1", "port2", "protocol"],
    "http": ["request_method", "request_uri", "host", "authorization", "request|file_data", "response_code", "response|file_data"],
    "mqtt": ["hdrflags", "topic", 'msg', ],
    "udp": ["request_length", "response_length"],
}

abstract_feature_list = ["http.authorization", "http.request|file_data", "http.response|file_data",
                         "mqtt.msg"]
