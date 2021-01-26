#!/usr/bin/python3
import time
import socket
import sys
import re
import logging
import argparse
from IPy import IP
import os.path
import threading
import signal
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client.core import REGISTRY


class haproxyCollector(object):
    def __init__(self, args):
        self.stats_socket = find_stats_socket(args.config_file)
        self.config_file = args.config_file
        self.aggregate = args.aggregate
        self.ha_stats = haproxy_Stats(self.stats_socket, self.config_file)

    def exit_gracefully(self, signum, frame):
        print("Closing down...")
        self.kill_now = True
        sys.exit(1)

    def collect_metric(self, metric, metric_collector, stick_tables):
        for table in stick_tables:
            # check first entry of the table if it contains the metric
            if len(stick_tables[table]) > 0:
                # detect _rate columns and tag them with their period
                if metric.endswith('_rate'):
                    rates = []
                    for column in stick_tables[table][0].keys():
                        if column.startswith(metric):
                            p = re.compile(r'\w+\((?P<period>\d+)\)')
                            m = p.search(column)
                            rates.append(m.group('period'))
                    for rate in rates:
                        for entry in stick_tables[table]:
                            metric_collector['family'].add_metric(
                                [table, self.agg_key(entry['key']), rate],
                                metric_collector['valuetype'](
                                    entry["%s(%s)" % (metric, rate)]
                                )
                            )
                elif metric in stick_tables[table][0].keys():
                    for entry in stick_tables[table]:
                        metric_collector['family'].add_metric(
                            [table, self.agg_key(entry['key'])],
                            metric_collector['valuetype'](
                                entry[metric]
                            )
                        )
        return metric_collector['family']

    def agg_key(self, key_value):
        if not self.aggregate:
            return key_value
        try:
            ip = IP(key_value)
            if ip.version == 6:
                return key_value
            else:
                return key_value
        except:
            return key_value

    def collect(self):
        logging.debug("Collecting...")
        tables = self.ha_stats.get_ha_sticky_tables()
        if tables is not False:
            logging.debug("got %d table(s): %s" % (len(tables), [table['table'] for table in tables]))

            yield self.collect_table_max_size(tables)
            yield self.collect_table_used_size(tables)

            stick_tables = self.ha_stats.get_ha_table_entries(tables)

            metrics = {}
            metrics['server_id'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_server_id',
                'Haproxy stick table key server association id',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['exp'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_expiry_milliseconds',
                'Haproxy stick table key expires in ms',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['use'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_use',
                'HAProxy stick table key use',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['gpc0'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_gpc0',
                'Haproxy stick table key general purpose counter 0',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['gpc0_rate'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_gpc0_rate',
                'Haproxy stick table key general purpose counter 0 rate',
                labels=["table", "key", "period"]),
                'valuetype': int}
            metrics['conn_cnt'] = {'family': CounterMetricFamily(
                'haproxy_stick_table_key_conn_total',
                'Haproxy stick table key connection counter',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['conn_rate'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_conn_rate',
                'Haproxy stick table key connection rate',
                labels=["table", "key", "period"]),
                'valuetype': int}
            metrics['conn_cur'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_conn_cur',
                'Number of concurrent connection for a given key',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['sess_cnt'] = {'family': CounterMetricFamily(
                'haproxy_stick_table_key_sess_total',
                'Number of concurrent sessions for a given key',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['sess_rate'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_sess_rate',
                'Haproxy stick table key session rate',
                labels=["table", "key", "period"]),
                'valuetype': int}
            metrics['http_req_cnt'] = {'family': CounterMetricFamily(
                'haproxy_stick_table_key_http_req_total',
                'Haproxy stick table key http request counter',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['http_req_rate'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_http_req_rate',
                'Haproxy stick table key http request rate',
                labels=["table", "key", "period"]),
                'valuetype': int}
            metrics['http_err_cnt'] = {'family': CounterMetricFamily(
                'haproxy_stick_table_key_http_err_total',
                'Haproxy stick table key http error counter',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['http_err_rate'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_http_err_rate',
                'Haproxy stick table key http error rate',
                labels=["table", "key", "period"]),
                'valuetype': int}
            metrics['bytes_in_cnt'] = {'family': CounterMetricFamily(
                'haproxy_stick_table_key_bytes_in_total',
                'Haproxy stick table key bytes in counter',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['bytes_in_rate'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_bytes_in_rate',
                'Haproxy stick table key bytes in rate',
                labels=["table", "key", "period"]),
                'valuetype': int}
            metrics['bytes_out_cnt'] = {'family': CounterMetricFamily(
                'haproxy_stick_table_key_bytes_out_total',
                'Haproxy stick table key bytes out counter',
                labels=["table", "key"]),
                'valuetype': int}
            metrics['bytes_out_rate'] = {'family': GaugeMetricFamily(
                'haproxy_stick_table_key_bytes_out_rate',
                'Haproxy stick table key bytes out rate',
                labels=["table", "key", "period"]),
                'valuetype': int}

            for metric in metrics.items():
                yield self.collect_metric(metric[0], metric[1], stick_tables)

        # Special metrics for table rules
        ratelimit_conditions = self.ha_stats.load_haproxy_table_rule()
        if ratelimit_conditions is not False:
            yield self.collect_table_rate_condition(ratelimit_conditions)

    def collect_table_used_size(self, tables):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_used_size',
            'HAProxy stick tables entries in use',
            labels=["table"])

        for table in tables:
            metric.add_metric([table['table']], int(table['used']))

        return metric

    def collect_table_max_size(self, tables):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_max_size',
            'HAProxy stick table maximum entries',
            labels=["table"])

        for table in tables:
            metric.add_metric([table['table']], int(table['size']))

        return metric

    def collect_table_rate_condition(self, ratelimit_conditions):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_rate_condition',
            'Stick table rate condition',
            labels=["table", "type", "action"])

        try:
            for table in ratelimit_conditions:
                for table_type in ratelimit_conditions[table]:
                    metric.add_metric(
                        [
                            table,
                            table_type,
                            ratelimit_conditions[table][table_type]['action']
                        ],
                        int(ratelimit_conditions[table][table_type]['value'])
                    )
        except KeyError as f:
            pass

        return metric


class haproxy_Stats(object):
    def __init__(self, stats_socket, config_file):
        self.stats_socket = stats_socket
        self.config_file = config_file
        self.conn_rate = {}
        self.ticks = time.time()

    def connect_to_ha_socket(self, cmd):
        """ Connect to HAProxy stats socket """
        try:
            unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix_socket.settimeout(0.1)
            unix_socket.connect(self.stats_socket)
            cmd += ' \n'
            unix_socket.send(cmd.encode())
            file_handle = unix_socket.makefile()
        except (ConnectionRefusedError,
                PermissionError,
                socket.timeout,
                OSError
                ) as e:
            logging.debug(e)
            return False
        else:
            try:
                data = file_handle.read().splitlines()
            except (ConnectionResetError,
                    ConnectionRefusedError,
                    PermissionError,
                    socket.timeout,
                    OSError
                    ) as e:
                logging.debug(e)
                return False
        finally:
            unix_socket.close()

        return data

    def get_ha_sticky_tables(self):
        """
        Get a List of all HAProxy stick tables

        Returns:
            A list with Haproxy stick tables, each item
            contains a dict with key values
            [{' table': ' table_name', ' type': ' ip',
            ' size': '204800', ' used': '0'}]
        """

        try:
            raw_tables = self.connect_to_ha_socket('show table')
            if raw_tables:
                tables = []
                for line in raw_tables:
                    table_dict = {}
                    for item in line.split(','):
                        data = item.split(':')
                        if len(data) == 2:
                            key = data[0].strip('#').strip(' ')
                            value = data[1].strip(' ')
                            table_dict.update({key: value})

                    if table_dict:
                        tables.append(table_dict)
                return tables
            else:
                return False
        except IndexError:
            return False
        except TypeError:
            logging.error(
                'Failed to connect to HAProxy Socket: {}'.format(
                    self.stats_socket
                )
            )
            return False

    def get_ha_table_entries(self, tables):
        """
        Get a list of entries in stick table for all tables

        Returns:
            A dict pr table, with a list of entries in the sticky table
        {'table1': [], 'table2': [{'key': '127.0.0.1', 'use': '0',
        'exp': '1343045', 'server_id': '1'}]}
        """
        try:
            stick_tables = {}
            for table in tables:
                table_entries = []
                raw_tables = self.connect_to_ha_socket(
                    'show table {}'.format(table['table'])
                )
                if raw_tables:
                    for line in raw_tables:
                        item_dict = {}
                        for item in line.split(' '):
                            if '=' in item:
                                data = item.split('=')
                                if len(data) == 2:
                                    key = data[0].strip(' ')
                                    value = data[1].strip(' ')
                                    item_dict.update({key: value})
                        if item_dict:
                            table_entries.append(item_dict)
                    stick_tables.update({table['table']: table_entries})
            return stick_tables
        except IndexError:
            return False

    def load_haproxy_table_rule(self):
        last_update = time.time() - self.ticks
        if last_update < 300 and self.conn_rate:
            return self.conn_rate
        else:
            try:
                with open(self.config_file) as f:
                    config = f.read()
            except FileNotFoundError:
                logging.fatal('Haproxy config not found')
                return False

            self.conn_rate = {}
            for line in config.split('\n'):
                if 'listen' in line.lower():
                    current_block = line.split(' ')[1]
                    self.conn_rate[current_block] = {}
                elif 'tcp-request content reject if' in line.lower():
                    p = re.compile(
                        r'{\s+(src_)?(?P<type>\w+)\s+'
                        r'(?P<action>\w+)\s+(?P<value>\w+)'
                    )
                    m = p.search(line)

                    if m.group('type') is None:
                        continue
                    type_counter = m.group('type')
                    conn_rate = {}
                    self.conn_rate[current_block][type_counter] = conn_rate

                    if m.group('action') is None:
                        continue
                    conn_rate['action'] = m.group('action')
                    if m.group('value') is None:
                        continue
                    conn_rate['value'] = m.group('value')

            self.ticks = time.time()
            return self.conn_rate


def find_stats_socket(config_file):
    sleep_timer = 100
    try:
        while not os.path.exists(config_file) and sleep_timer > 0:
            sleep_timer = sleep_timer - 1
            logging.error("config file not present, sleeping {} more times".format(sleep_timer))
            time.sleep(5)
    except (KeyboardInterrupt, SystemExit):
        logging.fatal('Kill signal received, closing down...')
        sys.exit(1)
    try:
        with open(config_file) as f:
            config = f.read()
    except FileNotFoundError:
        logging.fatal('Haproxy config not found')
        sys.exit(1)
    stats = re.findall(r'\s+stats\s+socket\s+((\/\w+\.?\w+){0,6})', config)
    if stats:
        return stats[0][0]
    else:
        return None


def exit_gracefully(signum, frame):
    logging.fatal('Kill signal received, closing down...')
    sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    logging.basicConfig(level=logging.DEBUG, format=log_format)
    parser = argparse.ArgumentParser(
        description="HAProxy stick table exporter"
    )
    parser.add_argument('-m', '--metrics-port', type=int, default=9366)
    parser.add_argument('-c', '--config-file', type=str, default="/etc/haproxy/haproxy.cfg")
    parser.add_argument('-a', '--aggregate', type=bool, default=False)
    args = parser.parse_args()

    logging.info(
        'Starting HAProxy sticky table exporter on port {} config-file {}'.format(
            args.metrics_port,
            args.config_file
        )
    )
    try:
        stats_socket = find_stats_socket(args.config_file)
        if stats_socket is None:
            logging.fatal('Unable to find stats socket')
            sys.exit(1)
        sleep_timer = 100
        while not os.path.exists(stats_socket) and sleep_timer > 0:
            sleep_timer = sleep_timer - 1
            logging.error('Stats socket not present. Sleeping')
            time.sleep(1)
        REGISTRY.register(haproxyCollector(args))
        start_http_server(args.metrics_port)
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt as k:
            logging.info('Exiting HAProxy stick table exporter')
            print('  Exiting exporter')
            break
