#!/usr/bin/env python
#
# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://sam.zoy.org/wtfpl/COPYING for more details.

import json
import operator
import sys
import os
from optparse import OptionParser, OptionGroup
import urllib
import re
from abc import abstractmethod

class BaseFilter(object):
    @abstractmethod
    def accept(self, relay):
        pass

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
    def accept(self, relay):
        if relay.get('bandwidth_rate', -1) < 12500 * 1024:
            return False
        if relay.get('advertised_bandwidth', -1) < 5000 * 1024:
            return False
        relevant_ports = set([80, 443, 554, 1755])
        summary = relay.get('exit_policy_summary', {})
        if 'accept' in summary:
            portlist = summary['accept']
        elif 'reject' in summary:
            portlist = summary['reject']
        else:
            return False
        ports = []
        for p in portlist:
            if '-' in p:
                ports.extend(range(int(p.split('-')[0]),
                                   int(p.split('-')[1]) + 1))
            else:
                ports.append(int(p))
        policy_ports = set(ports)
        if 'accept' in summary and not relevant_ports.issubset(policy_ports):
            return False
        if 'reject' in summary and not relevant_ports.isdisjoint(policy_ports):
            return False
        return True

class RelayStats(object):
    def __init__(self, options):
        self._data = None
        self._filters = self._create_filters(options)
        self._get_group = self._get_group_function(options)
        self._relays = None

    @property
    def data(self):
        if not self._data:
            self._data = json.load(file(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'details.json')))
        return self._data

    @property
    def relays(self):
        if self._relays:
            return self._relays

        self._relays = {}
        for relay in self.data['relays']:
            accepted = True
            for f in self._filters:
                if not f.accept(relay):
                    accepted = False
                    break
            if accepted:
                self.add_relay(relay)
        return self._relays

    def _create_filters(self, options):
        filters = []
        if not options.inactive:
            filters.append(RunningFilter())
        if options.family:
            filters.append(FamilyFilter(options.family, self.data['relays']))
        if options.country:
            filters.append(CountryFilter(options.country))
        if options.ases:
            filters.append(ASFilter(options.ases))
        if options.exits_only:
            filters.append(ExitFilter())
        if options.guards_only:
            filters.append(GuardFilter())
        if options.fast_exits_only:
            filters.append(FastExitFilter())
        return filters

    def _get_group_function(self, options):
        if options.by_country and options.by_as:
            return lambda relay: (relay.get('country', None), relay.get('as_number', None))
        elif options.by_country:
            return lambda relay: relay.get('country', None)
        elif options.by_as:
            return lambda relay: relay.get('as_number', None)
        else:
            return lambda relay: relay.get('fingerprint')

    def add_relay(self, relay):
        key = self._get_group(relay)
        if key not in self._relays:
            self._relays[key] = []
        self._relays[key].append(relay)

    def format_and_sort_groups(self, grouped_relays, by_country=False, by_as_number=False, links=False):
        formatted_groups = {}
        for group in grouped_relays.values():
            group_weights = (0, 0, 0, 0, 0)
            relays_in_group = 0
            for relay in group:
                weights = (relay.get('consensus_weight_fraction', 0),
                           relay.get('advertised_bandwidth_fraction', 0),
                           relay.get('guard_probability', 0),
                           relay.get('middle_probability', 0),
                           relay.get('exit_probability', 0))
                group_weights = tuple(sum(x) for x in zip(group_weights, weights))
                nickname = relay['nickname']
                fingerprint = relay['fingerprint'] if not links else "https://atlas.torproject.org/#details/%s" % relay['fingerprint']
                exit = 'Exit' if 'Exit' in set(relay['flags']) else '-'
                guard = 'Guard' if 'Guard' in set(relay['flags']) else '-'
                country = relay.get('country', '')
                as_number = relay.get('as_number', '')
                as_name = relay.get('as_name', '')
                relays_in_group += 1
            if by_country or by_as_number:
                nickname = "(%d relays)" % relays_in_group
                fingerprint = "*"
                exit = "*"
                guard = "*"
            if by_country and not by_as_number:
                as_number = "*"
                as_name = "*"
            if by_as_number and not by_country:
                country = "*"
            if links:
                format_string = "%8.4f%% %8.4f%% %8.4f%% %8.4f%% %8.4f%% %-19s %-78s %-4s %-5s %-2s %-9s %s"
            else:
                format_string = "%8.4f%% %8.4f%% %8.4f%% %8.4f%% %8.4f%% %-19s %-40s %-4s %-5s %-2s %-9s %s"
            formatted_group = format_string % (
                              group_weights[0] * 100.0,
                              group_weights[1] * 100.0,
                              group_weights[2] * 100.0,
                              group_weights[3] * 100.0,
                              group_weights[4] * 100.0,
                              nickname, fingerprint,
                              exit, guard, country, as_number, as_name)
            formatted_groups[formatted_group] = group_weights
        sorted_groups = sorted(formatted_groups.iteritems(), key=operator.itemgetter(1))
        sorted_groups.reverse()
        return sorted_groups

    def print_groups(self, sorted_groups, count=10, by_country=False, by_as_number=False, short=False, links=False):
        output_string = []
        if links:
            output_string.append("       CW    adv_bw   P_guard  P_middle    P_exit Nickname            Link                                                                           Exit Guard CC AS_num    AS_name"[:short])
        else:
            output_string.append("       CW    adv_bw   P_guard  P_middle    P_exit Nickname            Fingerprint                              Exit Guard CC AS_num    AS_name"[:short])
        if count < 0: count = len(sorted_groups)
        for formatted_group, weight in sorted_groups[:count]:
            output_string.append(formatted_group[:short])
        if len(sorted_groups) > count:
            if by_country and by_as_number:
                type = "countries and ASes"
            elif by_country:
                type = "countries"
            elif by_as_number:
                type = "ASes"
            else:
                type = "relays"
            other_weights = (0, 0, 0, 0, 0)
            for _, weights in sorted_groups[count:]:
                other_weights = tuple(sum(x) for x in zip(other_weights, weights))
            output_string.append("%8.4f%% %8.4f%% %8.4f%% %8.4f%% %8.4f%% (%d other %s)" % (
                  other_weights[0] * 100.0, other_weights[1] * 100.0,
                  other_weights[2] * 100.0, other_weights[3] * 100.0,
                  other_weights[4] * 100.0, len(sorted_groups) - count, type))
        selection_weights = (0, 0, 0, 0, 0)
        for _, weights in sorted_groups:
            selection_weights = tuple(sum(x) for x in zip(selection_weights, weights))
        if len(sorted_groups) > 1 and selection_weights[0] < 0.999:
            output_string.append("%8.4f%% %8.4f%% %8.4f%% %8.4f%% %8.4f%% (total in selection)" % (
                  selection_weights[0] * 100.0, selection_weights[1] * 100.0,
                  selection_weights[2] * 100.0, selection_weights[3] * 100.0,
                  selection_weights[4] * 100.0))
        return output_string

def create_option_parser():
    parser = OptionParser()
    parser.add_option("-d", "--download", action="store_true",
                      help="download details.json from Onionoo service")
    group = OptionGroup(parser, "Filtering options")
    group.add_option("-i", "--inactive", action="store_true", default=False,
                     help="include relays in selection that aren't currently running")
    group.add_option("-a", "--as", dest="ases", action="append",
                     help="select only relays from autonomous system number AS",
                     metavar="AS")
    group.add_option("-c", "--country", action="append",
                     help="select only relays from country with code CC", metavar="CC")
    group.add_option("-e", "--exits-only", action="store_true",
                     help="select only relays suitable for exit position")
    group.add_option("-f", "--family", action="store", type="string", metavar="RELAY",
                     help="select family by fingerprint or nickname (for named relays)")
    group.add_option("-g", "--guards-only", action="store_true",
                     help="select only relays suitable for guard position")
    group.add_option("-x", "--fast-exits-only", action="store_true",
                     help="select only 100+ Mbit/s exits allowing ports 80, 443, 554, and 1755")
    parser.add_option_group(group)
    group = OptionGroup(parser, "Grouping options")
    group.add_option("-A", "--by-as", action="store_true", default=False,
                     help="group relays by AS")
    group.add_option("-C", "--by-country", action="store_true", default=False,
                     help="group relays by country")
    parser.add_option_group(group)
    group = OptionGroup(parser, "Display options")
    group.add_option("-l", "--links", action="store_true",
                     help="display links to the Atlas service instead of fingerprints")
    group.add_option("-t", "--top", type="int", default=10, metavar="NUM",
                     help="display only the top results (default: %default; -1 for all)")
    group.add_option("-s", "--short", action="store_true",
                     help="cut the length of the line output at 70 chars")
    parser.add_option_group(group)
    return parser

def download_details_file():
    url = urllib.urlopen('https://onionoo.torproject.org/details?type=relay')
    details_file = open("details.json", 'w')
    details_file.write(url.read())
    url.close()
    details_file.close()

if '__main__' == __name__:
    parser = create_option_parser()
    (options, args) = parser.parse_args()
    if len(args) > 0:
        parser.error("Did not understand positional argument(s), use options instead.")

    if options.family and not re.match(r'^[A-F0-9]{40}$', options.family) and not re.match(r'^[A-Za-z0-9]{1,19}$', options.family):
        parser.error("Not a valid fingerprint or nickname: %s" % options.family)
    if options.download:
        download_details_file()
        print "Downloaded details.json.  Re-run without --download option."
        exit()

    if not os.path.exists('details.json'):
        parser.error("Did not find details.json.  Re-run with --download.")

    stats = RelayStats(options)
    sorted_groups = stats.format_and_sort_groups(stats.relays,
                    by_country=options.by_country,
                    by_as_number=options.by_as,
                    links=options.links)
    output_string = stats.print_groups(sorted_groups, options.top,
                       by_country=options.by_country,
                       by_as_number=options.by_as,
                       short=70 if options.short else None,
                       links=options.links)
    print '\n'.join(output_string)
