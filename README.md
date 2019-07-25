# This is file discovery implementation utilizing VMware tags for Prometheus discovery

This repository utilizes code from Ansible VMware inventory and has been modified to work for Prometheus. It can be slow in large vmware environments.

An example of how to use it for Promethues operator:

```apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata:
  labels:
    prometheus: monitoring-prometheus-filesd
  name: monitoring-prometheus-filesd
spec:
  containers:
    - name: file-sd
      image: vmware-filesd
      env:
        - name: HOSTNAME
          value: ""
        - name: USERNAME
          value: ""
        - name: PASSWORD
          value: ""
        - name: FILENAME
          value: "/opt/config/output.json"
      volumeMounts:
      - name: config-out
        mountPath: /opt/config
        readOnly: false
  securityContext:
    fsGroup: 2000
    runAsNonRoot: true
    runAsUser: 1000
  serviceAccountName: monitoring-prometheus-oper-prometheus
  serviceMonitorNamespaceSelector: {}
  serviceMonitorSelector:
    matchLabels:
      release: filesd-test
  replicas: 1
  alerting:
    alertmanagers:
    - namespace: default
      name: monitoring-prometheus-oper-alertmanager
      port: web
  additionalScrapeConfigs:
    name: monitoring-prometheus-oper-prometheus-scrape-confg
    key: additional-scrape-configs.yaml
```

It can also be called from the commandline directly: `python3 dynamic.py --hostname $HOSTNAME --username $USERNAME --password $PASSWORD --file $FILENAME --loop`