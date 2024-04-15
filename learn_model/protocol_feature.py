feature_dict = {
    "record": ["number", "response_number"],
    "common": ["src", "srcport", "dst", "domain", "dstport", "protocol"],
    "http": ["request_method", "host", "request_uri"],
    "mqtt": ["hdrflags", "topic"],
    "tcp": ["flags", "len"],
    "udp": ["length"],
}
