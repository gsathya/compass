import itertools

from config import *

class BaseFilter(object):
    def accept(self, relay):
        raise NotImplementedError("This isn't implemented by the subclass")

    def load(self, relays):
        return filter(self.accept, relays)

class RunningFilter(BaseFilter):
    def accept(self, relay):
        return relay['running']

class FamilyFilter(BaseFilter):
    def __init__(self, family, all_relays):
        self._family_fingerprint = None
        self._family_nickname = None
        self._family_relays = []
        found_relay = None
        for relay in all_relays:
            if len(family) == 40 and relay['fingerprint'] == family:
                found_relay = relay
                break
            if len(family) < 20 and 'Named' in relay['flags'] and relay['nickname'] == family:
                found_relay = relay
                break
        if found_relay:
            self._family_fingerprint = '$%s' % found_relay['fingerprint']
            if 'Named' in found_relay['flags']:
                self._family_nickname = found_relay['nickname']
            self._family_relays = [self._family_fingerprint] + found_relay.get('family', [])

    def accept(self, relay):
        fingerprint = '$%s' % relay['fingerprint']
        mentions = [fingerprint] + relay.get('family', [])
        # Only show families as accepted by consensus (mutually listed relays)
        listed = fingerprint in self._family_relays
        listed = listed or 'Named' in relay['flags'] and relay['nickname'] in self._family_relays
        mentioned = self._family_fingerprint in mentions
        mentioned = mentioned or self._family_nickname in mentions
        if listed and mentioned:
            return True
        return False

class CountryFilter(BaseFilter):
    def __init__(self, countries=[]):
        self._countries = [x.lower() for x in countries]

    def accept(self, relay):
        return relay.get('country', None) in self._countries

class ASFilter(BaseFilter):
    def __init__(self, as_sets=[]):
        self._as_sets = [x if not x.isdigit() else "AS" + x for x in as_sets]

    def accept(self, relay):
        return relay.get('as_number', None) in self._as_sets

class ExitFilter(BaseFilter):
    def accept(self, relay):
        return relay.get('exit_probability', -1) > 0.0

class GuardFilter(BaseFilter):
    def accept(self, relay):
        return relay.get('guard_probability', -1) > 0.0

class FastExitFilter(BaseFilter):
    class Relay(object):
        def __init__(self, relay):
            self.exit = relay.get('exit_probability')
            self.fp = relay.get('fingerprint')
            self.relay = relay

    def __init__(self, bandwidth_rate=FAST_EXIT_BANDWIDTH_RATE,
                 advertised_bandwidth=FAST_EXIT_ADVERTISED_BANDWIDTH,
                 ports=FAST_EXIT_PORTS):
        self.bandwidth_rate = bandwidth_rate
        self.advertised_bandwidth = advertised_bandwidth
        self.ports = ports

    def load(self, all_relays):
        # First, filter relays based on bandwidth and port requirements.
        matching_relays = []
        for relay in all_relays:
            if relay.get('bandwidth_rate', -1) < self.bandwidth_rate:
                continue
            if relay.get('advertised_bandwidth', -1) < self.advertised_bandwidth:
                continue
            relevant_ports = set(self.ports)
            summary = relay.get('exit_policy_summary', {})
            if 'accept' in summary:
                portlist = summary['accept']
            elif 'reject' in summary:
                portlist = summary['reject']
            else:
                continue
            ports = []
            for p in portlist:
                if '-' in p:
                    ports.extend(range(int(p.split('-')[0]),
                                       int(p.split('-')[1]) + 1))
                else:
                    ports.append(int(p))
            policy_ports = set(ports)
            if 'accept' in summary and not relevant_ports.issubset(policy_ports):
                continue
            if 'reject' in summary and not relevant_ports.isdisjoint(policy_ports):
                continue
            matching_relays.append(relay)
        return matching_relays

class SameNetworkFilter(BaseFilter):
    def __init__(self, orig_filter, max_per_network=FAST_EXIT_MAX_PER_NETWORK):
        self.orig_filter = orig_filter
        self.max_per_network = max_per_network

    def load(self, all_relays):
        network_data = {}
        for relay in self.orig_filter.load(all_relays):
            or_addresses = relay.get("or_addresses")
            no_of_addresses = 0
            for ip in or_addresses:
                ip, port = ip.rsplit(':', 1)
                # skip if ipv6
                if ':' in ip:
                    continue
                no_of_addresses += 1
                if no_of_addresses > 1:
                    print "[WARNING] - %s has more than one IPv4 OR address - %s" % relay.get("fingerprint"), or_addresses
                network = ip.rsplit('.', 1)[0]
                if network_data.has_key(network):
                    if len(network_data[network]) >= FAST_EXIT_MAX_PER_NETWORK:
                        # assume current relay to have smallest exit_probability
                        min_exit = relay.get('exit_probability')
                        min_id = -1
                        for id, value in enumerate(network_data[network]):
                            if value.get('exit_probability') < min_exit:
                                min_exit = value.get('exit_probability')
                                min_id = id
                        if min_id != -1:
                            del network_data[network][min_id]
                            network_data[network].append(relay)
                    else:
                        network_data[network].append(relay)
                else:
                    network_data[network] = [relay]
        return list(itertools.chain.from_iterable(network_data.values()))

class InverseFilter(BaseFilter):
    def __init__(self, orig_filter):
        self.orig_filter = orig_filter

    def load(self, all_relays):
        matching_relays = self.orig_filter.load(all_relays)
        inverse_relays = []
        for relay in all_relays:
            if relay not in matching_relays:
                inverse_relays.append(relay)
        return inverse_relays
