# Pass the official PostgreSQL 18.6 bookworm multi-arch digest. No floating base.
ARG POSTGRES_IMAGE=postgres:18.6-bookworm@sha256:5c4783a8cc3f0074912164f94dfa1be4e043438f0f707cf968d7af9a0d31a2c8
FROM ${POSTGRES_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/patroni
COPY requirements.lock /tmp/patroni-requirements.lock
RUN /opt/patroni/bin/pip install --no-cache-dir --require-hashes -r /tmp/patroni-requirements.lock \
    && rm /tmp/patroni-requirements.lock
RUN /opt/patroni/bin/patroni --version && postgres --version && pg_basebackup --version && pg_verifybackup --version && pg_waldump --version \
    && /opt/patroni/bin/python -c "import patroni.dcs.etcd3, psycopg, cryptography"
RUN install -d -m 0755 /usr/local/lib/rauth
COPY --chmod=0444 entrypoint.py archive.py pki_renew.py backup.py /usr/local/lib/rauth/
USER 999:999
RUN /opt/patroni/bin/python -c "import runpy; runpy.run_path('/usr/local/lib/rauth/entrypoint.py'); runpy.run_path('/usr/local/lib/rauth/archive.py'); runpy.run_path('/usr/local/lib/rauth/pki_renew.py'); runpy.run_path('/usr/local/lib/rauth/backup.py')"
ENTRYPOINT ["/opt/patroni/bin/python", "/usr/local/lib/rauth/entrypoint.py"]
