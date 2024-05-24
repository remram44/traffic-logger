import logging
import os.path
import requests
from time import sleep, time

from k8s_traffic_logger.capture import get_traffic_counters_ipv4, get_traffic_counters_ipv6
from k8s_traffic_logger.k8s import K8sPodWatcher


logger = logging.getLogger('k8s_traffic_logger.main')

logging.root.handlers.clear()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


INFLUXDB_ENDPOINT = os.environ['INFLUXDB_ENDPOINT']
INFLUXDB_BEARER_TOKEN = os.environ['INFLUXDB_BEARER_TOKEN']


INFLUXDB_HEADERS = {
    'Authorization': f'Token {INFLUXDB_BEARER_TOKEN}',
    'Content-Type': 'text/plain; charset=utf-8',
    'Accept': 'application/json',
}

HOSTNAME = os.environ['HOSTNAME']


k8s_data = K8sPodWatcher(HOSTNAME)


class InfluxLineProtocolWriter(object):
    def __init__(self, *, timestamp=None):
        if timestamp is None:
            self._timestamp = int(float(time()) * 10**9)
        else:
            self._timestamp = timestamp
        self._lines = []

    def add_measurement(self, measurement, tags, fields):
        timestamp = self._timestamp

        if tags:
            tags_str = ',' + ','.join(f'{k}={v}' for k, v in tags.items())
        else:
            tags_str = ''

        fields_str = ','.join(f'{k}={v}' for k, v in fields.items())

        self._lines.append(
            f'{measurement}{tags_str} {fields_str} {timestamp}',
        )

    def as_string(self):
        return '\n'.join(self._lines)


exiting = False
while not exiting:
    try:
        sleep(10)
    except KeyboardInterrupt:
        exiting = True

    ipv4_throughput = get_traffic_counters_ipv4()
    ipv6_throughput = get_traffic_counters_ipv6()

    ipv4_datapoints = InfluxLineProtocolWriter()
    for local_address, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
                                              key=lambda kv: sum(kv[1]),
                                              reverse=True):
        pod_namespace, pod_name = k8s_data.get_pod_from_ip(local_address)

        ipv4_datapoints.add_measurement(
            'traffic',
            dict(
                hostname=HOSTNAME,
                ip_version='4',
                local_address=local_address,
                namespace=pod_namespace,
                pod=pod_name,
            ),
            dict(
                sent_bytes=int(send_bytes),
                received_bytes=int(recv_bytes),
            ),
        )

    response = requests.post(
        INFLUXDB_ENDPOINT,
        headers=INFLUXDB_HEADERS,
        data=ipv4_datapoints.as_string(),
    )
    if response.status_code >= 400:
        logger.warning("HTTP error %d", response.status_code)

    ipv6_datapoints = InfluxLineProtocolWriter()
    for local_address, (send_bytes, recv_bytes) in sorted(ipv6_throughput.items(),
                                              key=lambda kv: sum(kv[1]),
                                              reverse=True):
        pod_namespace, pod_name = k8s_data.get_pod_from_ip(local_address)

        ipv6_datapoints.add_measurement(
            'traffic',
            dict(
                hostname=HOSTNAME,
                ip_version='6',
                local_address=local_address,
                namespace=pod_namespace,
                pod=pod_name,
            ),
            dict(
                sent_bytes=int(send_bytes),
                received_bytes=int(recv_bytes),
            )
        )

    response = requests.post(
        INFLUXDB_ENDPOINT,
        headers=INFLUXDB_HEADERS,
        data=ipv6_datapoints.as_string(),
    )
    if response.status_code >= 400:
        logger.warning("HTTP error %d", response.status_code)
