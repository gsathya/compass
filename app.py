import os
import re
import compass
from util import Result,Boolean,NullFn,Int,List,ResultEncoder,JSON
import json
from flask import Flask, request, jsonify, render_template,Response

app = Flask(__name__)

class Opt(object):
    request_types = {
      'by_as':Boolean,
      'by_country':Boolean,
      'inactive':Boolean,
      'exits_only':Boolean,
      'guards_only': Boolean,
      'links':Boolean,
      'sort':NullFn,
      'sort_reverse':Boolean,
      'top':Int,
      'family':NullFn,
      'ases':List,
      'country':JSON,
      'exit_filter':NullFn
    }

    @staticmethod
    def convert(key,val):
      return Opt.request_types[key](val)

    def __str__(self):
      return repr(self)

    def __repr__(self):
      return str(self.__dict__)

    def __init__(self,request):

      for key in Opt.request_types:
        if key in request:
          setattr(self,key,Opt.convert(key,request[key]))
        else:
          setattr(self,key,Opt.convert(key,None))

def parse(output_string, grouping=False, sort_key=None):
    results = []
    sorted_results = {}

    for id, line in enumerate(output_string):
        # skip headings
        if id == 0: continue

        result = Result()
        values = line.split()

        """
        This is a super weird hack. When we group by country or AS, the
        nickname is replaced with '(x relays)' which when split() creates
        ['(x','relays)']. I need to join this again and then left shift all
        the elements and delete the last element in the list.
        """
        if grouping:
            values[6] = "%s %s" % (values[6], values[7])
            for id in xrange(8, len(values)):
                values[id-1] = values[id]
            del values[-1]

        # TODO: change inaccurate value of 10
        if len(values) > 10:
            result.index = id
            result.cw = values[0]
            result.adv_bw = values[1]
            result.p_guard = values[2]
            result.p_middle = values[3]
            result.p_exit = values[4]
            result.nick = values[5]
            result.fp = values[6]
            result.exit = values[7]
            result.guard = values[8]
            result.cc = values[9]
            result.as_no = values[10]
            result.as_name = ' '.join(values[11:])
            result.as_name = re.sub(r'\([^)]*\)', '', result.as_name)
            result.as_info = "%s %s" % (result.as_no, result.as_name)

            if sort_key:
                key = float(getattr(result, sort_key)[:-1])
                if sorted_results.has_key(key):
                    sorted_results[key].append(result)
                else:
                    sorted_results[key] = [result]
            else:
                results.append(result)
        else:
            result.index = ""
            result.cw = values[0]
            result.adv_bw = values[1]
            result.p_guard = values[2]
            result.p_middle = values[3]
            result.p_exit = values[4]
            result.nick = ""
            result.fp = ' '.join(values[5:])
            result.exit = ""
            result.guard = ""
            result.cc = ""
            result.as_no = ""
            result.as_name = ""
            result.as_info = ""
            results.append(result)

    return results if results else sorted_results


@app.route('/')
def index():

    return app.open_resource("templates/index.html").read().replace('<!--%script_root%-->',request.script_root)

@app.route('/result.json', methods=['GET'])
def json_result():
    options = Opt(dict(request.args.items()))

    if "TESTING_DATAFILE" in app.config and "TESTING" in app.config:
      stats = compass.RelayStats(options,app.config['TESTING_DATAFILE'])
    else:
      stats = compass.RelayStats(options)

    results = stats.select_relays(stats.relays, options)

    relays = stats.sort_and_reduce(results,
                                   options)

    return Response(json.dumps(relays, cls=ResultEncoder), mimetype='application/json')

@app.route('/result', methods=['GET'])
def result():
    options = Opt()
    sort_key = None
    relays = []

    for key, value in request.args.items():
        if key == "top":
            try:
                options.top = int(value)
            except:
                options.top = -1
        elif key == "sort":
            sort_key = value
        elif key in ["country", "ases"]:
            if value:
                setattr(options, key, [value])
            else:
                setattr(options, key, None)
        elif key == "exits":
            setattr(options, value, True)
        else:
            setattr(options, key, value)

    stats = compass.RelayStats(options)
    sorted_groups = stats.format_and_sort_groups(stats.relays,
                        by_country=options.by_country,
                        by_as_number=options.by_as,
                        links=options.links)
    output_string = stats.print_groups(sorted_groups, options.top,
                   by_country=options.by_country,
                   by_as_number=options.by_as,
                   short=None,
                   links=None)
    results = parse(output_string, options.by_country or options.by_as, sort_key)
    if sort_key:
        for key in sorted(results.iterkeys(), reverse=True):
            for value in results[key]:
                relays.append(value)
    else:
        relays = results

    return render_template('result.html', results=relays, grouping=options.by_as or options.by_country)

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
