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
import util
import os
import urllib
import re
import itertools

from filters import *
from optparse import OptionParser, OptionGroup

class RelayStats(object):
    def __init__(self, options, custom_datafile="details.json"):
        self._data = None
        self._datafile_name = custom_datafile
        self._filters = self._create_filters(options)
        self._get_group = self._get_group_function(options)
        self._relays = None

    @property
    def data(self):
      if not self._data:
        self._data = json.load(file(os.path.join(os.path.dirname(os.path.abspath(__file__)), self._datafile_name)))
      return self._data

    @property
    def relays(self):
        if self._relays:
            return self._relays
        self._relays = {}
        relays = self.data['relays']
        for f in self._filters:
            relays = f.load(relays)
        for relay in relays:
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
        if options.exit_filter == 'all_relays':
            pass
        elif options.exit_filter == 'fast_exits_only':
            filters.append(SameNetworkFilter(FastExitFilter()))
        elif options.exit_filter == 'almost_fast_exits_only':
            filters.append(FastExitFilter(ALMOST_FAST_EXIT_BANDWIDTH_RATE,
                                          ALMOST_FAST_EXIT_ADVERTISED_BANDWIDTH,
                                          ALMOST_FAST_EXIT_PORTS))
            filters.append(InverseFilter(SameNetworkFilter(FastExitFilter())))
        elif options.exit_filter == 'fast_exits_only_any_network':
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

    WEIGHTS = ['consensus_weight_fraction', 'advertised_bandwidth_fraction', 'guard_probability', 'middle_probability', 'exit_probability']

    def print_selection(self,selection,options):
      """
      Print the selection returned by sort_and_reduce relays into a
      string for the command line version.
      """
      column_widths = [9,10,10,10,10,21,80 if options.links else 42,7,7,4,11]
      headings = ["CW","adv_bw","P_guard","P_middle", "P_exit", "Nickname",
                  "Link" if options.links else "Fingerprint",
                  "Exit","Guard","CC", "Autonomous System"]

      #Print the header
      header = "".join(word.ljust(column_widths[i]) for i,word in enumerate(headings))
      print(header[:options.short])

      for relay in selection['results']:
        line = "".join(field.ljust(column_widths[i])
              for i,field in
              enumerate(relay.printable_fields(options.links)))
        print(line[:options.short])

      #Print the 'excluded' set if we have it
      if selection['excluded']:
        line = "".join(field.ljust(column_widths[i])
              for i,field in
              enumerate(selection['excluded'].printable_fields()))
        print(line[:options.short])

      #Print the 'total' set if we have it
      if selection['total']:
        line = "".join(field.ljust(column_widths[i])
              for i,field in
              enumerate(selection['total'].printable_fields()))
        print(line[:options.short])

    def sort_and_reduce(self, relay_set, options):
      """
      Take a set of relays (has already been grouped and
      filtered), sort it and return the ones requested
      in the 'top' option.  Add index numbers to them as well.

      Returns a hash with three values:
        *results*: A list of Result objects representing the selected
                   relays
        *excluded*: A Result object representing the stats for the
                    filtered out relays. May be None
        *total*: A Result object representing the stats for all of the
                 relays in this filterset.
      """
      output_relays = list()
      excluded_relays = None
      total_relays = None

      # We need a simple sorting key function
      def sort_fn(r):
        return getattr(r,options.sort)

      relay_set.sort(key=sort_fn,reverse=options.sort_reverse)

      if options.top < 0:
        options.top = len(relay_set)

      # Set up to handle the special lines at the bottom
      excluded_relays = util.Result(zero_probs=True)
      total_relays = util.Result(zero_probs=True)
      if options.by_country and options.by_as:
          filtered = "countries and ASes"
      elif options.by_country:
          filtered = "countries"
      elif options.by_as:
          filtered = "ASes"
      else:
          filtered = "relays"

      # Add selected relays to the result set
      for i,relay in enumerate(relay_set):
        # We have no links if we're grouping
        if options.by_country or options.by_as:
          relay.link = False

        if i < options.top:
          relay.index = i + 1
          output_relays.append(relay)

        if i >= options.top:
          excluded_relays.p_guard += relay.p_guard
          excluded_relays.p_exit += relay.p_exit
          excluded_relays.p_middle += relay.p_middle
          excluded_relays.adv_bw += relay.adv_bw
          excluded_relays.cw += relay.cw

        total_relays.p_guard += relay.p_guard
        total_relays.p_exit += relay.p_exit
        total_relays.p_middle += relay.p_middle
        total_relays.adv_bw += relay.adv_bw
        total_relays.cw += relay.cw

        excluded_relays.nick = "(%d other %s)" % (
                                  len(relay_set) - options.top,
                                  filtered)
        total_relays.nick = "(total in selection)"

      # Only include the excluded line if
      if len(relay_set) <= options.top:
        excluded_relays = None

      # Only include the last line if
      if total_relays.cw > 99.9:
        total_relays = None

      return {
              'results': output_relays,
              'excluded': excluded_relays,
              'total': total_relays
              }


    def select_relays(self, grouped_relays, options):
      """
      Return a Pythonic representation of the relays result set. Return it as a set of Result objects.
      """
      results = []
      for group in grouped_relays.itervalues():
        #Initialize some stuff
        group_weights = dict.fromkeys(RelayStats.WEIGHTS, 0)
        relays_in_group, exits_in_group, guards_in_group = 0, 0, 0
        ases_in_group = set()
        result = util.Result()
        for relay in group:
            for weight in RelayStats.WEIGHTS:
                group_weights[weight] += relay.get(weight, 0)

            result.nick = relay['nickname']
            result.fp = relay['fingerprint']
            result.link = options.links

            if 'Exit' in set(relay['flags']) and not 'BadExit' in set(relay['flags']):
                result.exit = 'Exit'
                exits_in_group += 1
            else:
                result.exit = '-'
            if 'Guard' in set(relay['flags']):
                result.guard = 'Guard'
                guards_in_group += 1
            else:
                result.guard = '-'
            result.cc = relay.get('country', '??').upper()
            result.as_no = relay.get('as_number', '??')
            result.as_name = relay.get('as_name', '??')
            result.as_info = "%s %s" %(result.as_no, result.as_name)
            ases_in_group.add(result.as_info)
            relays_in_group += 1

        # If we want to group by things, we need to handle some fields
        # specially
        if options.by_country or options.by_as:
            result.nick = "*"
            result.fp = "(%d relays)" % relays_in_group
            result.exit = "(%d)" % exits_in_group
            result.guard = "(%d)" % guards_in_group
            if not options.by_as and not options.ases:
                result.as_info = "(%s)" % len(ases_in_group)
            if not options.by_country and not options.country:
                options.country = "*"

        #Include our weight values
        for weight in group_weights.iterkeys():
          result['cw'] = group_weights['consensus_weight_fraction'] * 100.0
          result['adv_bw'] = group_weights['advertised_bandwidth_fraction'] * 100.0
          result['p_guard'] = group_weights['guard_probability'] * 100.0
          result['p_middle'] = group_weights['middle_probability'] * 100.0
          result['p_exit'] = group_weights['exit_probability'] * 100.0

        results.append(result)

      return results

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
    group.add_option("--exit-filter",type="choice", dest="exit_filter",
                     choices=["fast_exits_only","almost_fast_exits_only",
                              "all_relays","fast_exits_only_any_network"],
                              metavar="{fast_exits_only|almost_fast_exits_only|all_relays|fast_exits_only_any_network}",
                     default='all_relays')
    group.add_option("--fast-exits-only", action="store_true",
                     help="select only fast exits (%d+ Mbit/s, %d+ KB/s, %s, %d- per /24)" %
                          (FAST_EXIT_BANDWIDTH_RATE / (125 * 1024),
                           FAST_EXIT_ADVERTISED_BANDWIDTH / 1024,
                           '/'.join(map(str, FAST_EXIT_PORTS)),
                           FAST_EXIT_MAX_PER_NETWORK))
    group.add_option("--almost-fast-exits-only", action="store_true",
                     help="select only almost fast exits (%d+ Mbit/s, %d+ KB/s, %s, not in set of fast exits)" %
                          (ALMOST_FAST_EXIT_BANDWIDTH_RATE / (125 * 1024),
                           ALMOST_FAST_EXIT_ADVERTISED_BANDWIDTH / 1024,
                           '/'.join(map(str, ALMOST_FAST_EXIT_PORTS))))
    group.add_option("--fast-exits-only-any-network", action="store_true",
                     help="select only fast exits without network restriction (%d+ Mbit/s, %d+ KB/s, %s)" %
                          (FAST_EXIT_BANDWIDTH_RATE / (125 * 1024),
                           FAST_EXIT_ADVERTISED_BANDWIDTH / 1024,
                           '/'.join(map(str, FAST_EXIT_PORTS))))
    parser.add_option_group(group)
    group = OptionGroup(parser, "Grouping options")
    group.add_option("-A", "--by-as", action="store_true", default=False,
                     help="group relays by AS")
    group.add_option("-C", "--by-country", action="store_true", default=False,
                     help="group relays by country")
    parser.add_option_group(group)
    group = OptionGroup(parser, "Sorting options")
    group.add_option("--sort", type="choice",
                     choices=["cw","adv_bw","p_guard","p_exit","p_middle",
                              "nick","fp"],
                     metavar="{cw|adv_bw|p_guard|p_exit|p_middle|nick|fp}",
                     default="cw",
                     help="sort by this field")
    group.add_option("--sort_reverse", action="store_true", default=True,
                     help="invert the sorting order")
    parser.add_option_group(group)
    group = OptionGroup(parser, "Display options")
    group.add_option("-l", "--links", action="store_true",
                     help="display links to the Atlas service instead of fingerprints")
    group.add_option("-t", "--top", type="int", default=10, metavar="NUM",
                     help="display only the top results (default: %default; -1 for all)")

    group.add_option("-s", "--short", action="store_const",dest='short',const=70,
                     help="cut the length of the line output at 70 chars")
    group.add_option("-j", "--json", action="store_true",
                     help="output in JSON rather than human-readable format")
    group.add_option("--datafile", default="details.json",
                     help="use a custom datafile (Default: 'details.json')")
    parser.add_option_group(group)
    return parser

def download_details_file():
    url = urllib.urlopen('https://onionoo.torproject.org/details?type=relay')
    details_file = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'details.json'), 'w')
    details_file.write(url.read())
    url.close()
    details_file.close()

def fix_exit_filter_options(options):
  """
  Translate the old-style exit filter options into
  the new format (as received on the front end).
  """
  if options.exit_filter != "all_relays":
    # We just accept this option's value
    return options

  fast_exit_options = 0
  if options.fast_exits_only:
    options.exit_filter = "fast_exits_only"
    fast_exit_options += 1
  if options.almost_fast_exits_only:
    options.exit_filter = "almost_fast_exits_only"
    fast_exit_options += 1
  if options.fast_exits_only_any_network:
    options.exit_filter = "fast_exits_only_any_network"
    fast_exit_options += 1

  if fast_exit_options > 1:
    raise Exception

  return options


if '__main__' == __name__:
    parser = create_option_parser()
    (options, args) = parser.parse_args()
    if len(args) > 0:
        parser.error("Did not understand positional argument(s), use options instead.")
    if options.family and not re.match(r'^[A-F0-9]{40}$', options.family) and not re.match(r'^[A-Za-z0-9]{1,19}$', options.family):
        parser.error("Not a valid fingerprint or nickname: %s" % options.family)

    try:
      options = fix_exit_filter_options(options)
    except:
        parser.error("Can only filter by one fast-exit option.")

    if options.download:
        download_details_file()
        print "Downloaded details.json.  Re-run without --download option."
        exit()
    if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'details.json')):
        parser.error("Did not find details.json.  Re-run with --download.")

    stats = RelayStats(options,options.datafile)
    results = stats.select_relays(stats.relays,options)

    sorted_results = stats.sort_and_reduce(results,options)

    if options.json:
      print(json.dumps(sorted_results,cls=util.ResultEncoder))
    else:
      stats.print_selection(sorted_results,options)
