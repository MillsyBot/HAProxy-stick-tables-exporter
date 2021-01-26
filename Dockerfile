ARG PYTHON_VERSION=python:3

FROM $PYTHON_VERSION

ENV PROM_PORT=9366
ENV HAPROXY_CONF="/etc/haproxy/haproxy.cfg"

RUN pip install prometheus_client requests pyyaml IPy

COPY haproxy-stick-tables-exporter.py /

CMD python3 /haproxy-stick-tables-exporter.py -m $PROM_PORT -c $HAPROXY_CONF