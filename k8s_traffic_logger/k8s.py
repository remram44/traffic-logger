from kubernetes import client, config, watch
import logging
import threading
import time


logger = logging.getLogger('k8s_traffic_logger.k8s')


config.load_kube_config()
v1 = client.CoreV1Api()


class K8sPodWatcher(object):
    def __init__(self, hostname):
        self._hostname = hostname
        self._pod_metadata = {}
        self._mutex = threading.Lock()

        with self._mutex:
            # Start watch thread
            watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
            watch_thread.start()

            # Do initial sync
            self._do_sync()

            # Start sync thread
            sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
            sync_thread.start()

    def _do_sync(self):
        logger.info("Doing full sync...")
        self._pod_metadata.clear()
        ret = v1.list_pod_for_all_namespaces(
            watch=False,
            field_selector=f'spec.nodeName={self._hostname}',
        )
        for pod in ret.items:
            if pod.status.pod_ip:
                logger.info(
                    "Pod: %s/%s %s",
                    pod.metadata.namespace,
                    pod.metadata.name,
                    pod.status.pod_ip,
                )
                self._pod_metadata[pod.status.pod_ip] = [
                    pod.metadata.namespace,
                    pod.metadata.name,
                ]
        logger.info("Full sync completed")

    def _watch_loop(self):
        w = watch.Watch()
        while True:
            try:
                for event in w.stream(
                    v1.list_pod_for_all_namespaces,
                    field_selector=f'spec.nodeName={self._hostname}',
                ):
                    with self._mutex:
                        self._handle_event(event)
            except client.ApiException as e:
                if e.status != 410:
                    raise

    def _sync_loop(self):
        """Does a fyll sync every 5 minutes.
        """
        while True:
            time.sleep(5 * 60)

            with self._mutex:
                self._do_sync()

    def _handle_event(self, event):
        pod = event['object']
        pod_ip = pod.status.pod_ip

        if event['type'] == 'DELETED':
            if pod_ip and pod_ip in self._pod_metadata:
                logger.info(
                    "Deleted pod: %s/%s %s",
                    pod.metadata.namespace,
                    pod.metadata.name,
                    pod_ip,
                )
                del self._pod_metadata[pod_ip]
        else:
            if pod_ip and pod_ip not in self._pod_metadata:
                logger.info(
                    "New pod: %s/%s %s",
                    pod.metadata.namespace,
                    pod.metadata.name,
                    pod_ip,
                )
                self._pod_metadata[pod_ip] = (
                    pod.metadata.namespace,
                    pod.metadata.name,
                )

    def get_pod_from_ip(self, pod_ip):
        with self._mutex:
            return self._pod_metadata[pod_ip]
