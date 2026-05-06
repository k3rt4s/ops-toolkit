# ELK Lab

This folder contains ELK/DVWA lab and class materials. The scripts are lab-only setup helpers for disposable Ubuntu/Debian hosts and are not production deployment automation.

## Scripts

| Script                                | Purpose                                                              |
| ------------------------------------- | -------------------------------------------------------------------- |
| `scripts\setup-elastic-stack-lab.sh`  | Install Elasticsearch and Kibana on a single lab host.               |
| `scripts\setup-filebeat-lab-agent.sh` | Install Filebeat on a lab endpoint and point it at the Elastic host. |
| `scripts\setup-dvwa-lab-target.sh`    | Install DVWA on a vulnerable lab target host.                        |

## Example Flow

Install the Elastic/Kibana lab host:

```bash
sudo ./scripts/setup-elastic-stack-lab.sh --cluster-name secops-lab --node-name elk01 --dry-run
sudo ./scripts/setup-elastic-stack-lab.sh --cluster-name secops-lab --node-name elk01
```

Install Filebeat on a lab endpoint:

```bash
sudo ./scripts/setup-filebeat-lab-agent.sh \
  --elastic-host https://elk01:9200 \
  --kibana-host http://elk01:5601 \
  --elastic-username elastic \
  --elastic-password '<lab-password>' \
  --elastic-ca-cert ./http_ca.crt \
  --dry-run
```

Install DVWA on a lab target:

```bash
sudo ./scripts/setup-dvwa-lab-target.sh --db-password '<lab-password>' --dry-run
```

## Notes

- Run these scripts only in isolated lab networks.
- Run each script with `--dry-run` first, then rerun without `--dry-run` after reviewing the plan.
- Review generated service and application configuration before reusing any pattern elsewhere.
- Elastic packages are installed from Elastic's apt repository.
- DVWA is intentionally vulnerable and must never be exposed to untrusted networks.
