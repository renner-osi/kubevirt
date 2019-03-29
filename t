apiVersion: kubevirt.io/v1alpha3
kind: VirtualMachine
metadata:
  labels:
    os: vmanage
    special: vmanage1
    topology: renner
  name: vmanage1
spec:
  running: true
  template:
    metadata:
      labels:
        os: vmanage
        special: vmanage1
        topology: renner
    spec:
      domain:
        devices:
          disks:
          - disk:
            name: registrydisk
          - disk:
            name: emptyDisk
          interfaces:
          - bridge: {}
            macAddress: 02:00:00:c4:99:8f
            name: default
        resources:
          limits:
            cpu: "1"
            memory: 8G
          requests:
            cpu: "1"
            memory: 8G
      networks:
      - name: default
        pod: {}
      volumes:
      - containerDisk:
          image: onesourceintegrations/viptela:manage-18.4.1
          imagePullSecret: dockerhub
        name: registrydisk
      - emptyDisk:
          capacity: 100G
        name: emptyDisk
